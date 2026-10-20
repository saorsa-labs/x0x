// Invoke in the private inventory_commands module. Standalone target: zero tests.
// These byte/argv controls do not read executable metadata, resolve unit merges,
// observe a service manager, or prove account/job/host population completeness.
#[allow(unused_macros)]
macro_rules! inventory_commands_regression_tests {
    () => {
        #[cfg(unix)]
        mod inventory_commands_regressions {
            use super::{parse_command, parse_source};
            use std::io::ErrorKind;
            use std::path::Path;

            const INSTALL: &str = "/owned/bin/x0xd";

            fn argv(arguments: &[&str]) -> Vec<String> {
                arguments.iter().map(|argument| (*argument).to_owned()).collect()
            }

            #[test]
            fn inventory_commands_keep_direct_literal_arguments() {
                let expected = argv(&[INSTALL, "--name", "owned team", "", "a\"b"]);
                let command = parse_command(Path::new(INSTALL), &expected, Path::new(INSTALL)).unwrap();
                assert_eq!(command.executable, Path::new(INSTALL));
                assert_eq!(command.argv, expected);
                let source = format!("[Service]\nExecStart=\"{INSTALL}\" --name 'owned team' \"\" 'a\"b'\n");
                let commands = parse_source("owned.service", source.as_bytes(), Path::new(INSTALL)).unwrap();
                assert_eq!(commands.len(), 1);
                assert_eq!(commands[0].property, "ExecStart");
                assert_eq!(commands[0].command.executable, Path::new(INSTALL));
                assert_eq!(commands[0].command.argv, expected);
            }

            #[test]
            fn inventory_commands_retain_all_exec_evidence_in_source_order() {
                let properties = ["ExecStart", "ExecStartPre", "ExecStartPost", "ExecCondition", "ExecReload", "ExecStop", "ExecStopPost"];
                let mut source = "[Service]\n".to_owned();
                for property in properties {
                    source.push_str(&format!("{property}={INSTALL} --name {property}\n"));
                }
                // A reset is not authority to erase evidence from this supplied
                // source; merged unit semantics belong to a later component.
                source.push_str("ExecStart=\n");
                let commands = parse_source("owned.service", source.as_bytes(), Path::new(INSTALL)).unwrap();
                assert_eq!(commands.len(), properties.len());
                for (index, property) in properties.into_iter().enumerate() {
                    assert_eq!(commands[index].property, property);
                    assert_eq!(commands[index].command.argv, argv(&[INSTALL, "--name", property]));
                }
                assert!(parse_source("owned.service", b"[Unit]\nDescription=no supplied command\n[Service]\nExecStart=\n", Path::new(INSTALL)).unwrap().is_empty());
            }

            #[test]
            fn inventory_commands_refuse_unknown_executable_authority() {
                for other in ["/owned/bin/helper", "/owned/missing", "/bin/sh", "/usr/bin/env", "/owned/bin/./x0xd", "/owned//bin/x0xd"] {
                    let arguments = argv(&[other, "literal"]);
                    assert_eq!(parse_command(Path::new(other), &arguments, Path::new(INSTALL)).unwrap_err().kind(), ErrorKind::Unsupported);
                    // Check an unknown command even after a direct command and
                    // even if a later empty assignment would reset that key.
                    let source = format!("[Service]\nExecStart={INSTALL}\nExecStartPre={other} literal\nExecStartPre=\n");
                    assert_eq!(parse_source("owned.service", source.as_bytes(), Path::new(INSTALL)).unwrap_err().kind(), ErrorKind::Unsupported);
                }
            }

            #[test]
            fn inventory_commands_require_absolute_consistent_executable_and_argv() {
                for (path, arguments, install) in [
                    (INSTALL, vec![], INSTALL),
                    (INSTALL, argv(&["/owned/bin/other"]), INSTALL),
                    (INSTALL, argv(&["/owned/bin/./x0xd"]), INSTALL),
                    ("x0xd", argv(&["x0xd"]), INSTALL),
                    (INSTALL, argv(&[INSTALL]), "x0xd"),
                    (INSTALL, argv(&["", INSTALL]), INSTALL),
                ] {
                    assert!(parse_command(Path::new(path), &arguments, Path::new(install)).is_err());
                }
            }

            #[test]
            fn inventory_commands_refuse_expansion_before_any_exclusion() {
                for argument in ["$BIN", "$$BIN", "%i", "%u", "literal%value"] {
                    assert!(parse_command(Path::new(INSTALL), &argv(&[INSTALL, argument]), Path::new(INSTALL)).is_err());
                    for property in ["ExecStart", "Environment", "WorkingDirectory"] {
                        let source = format!("[Service]\n{property}={argument}\n");
                        assert!(parse_source("owned.service", source.as_bytes(), Path::new(INSTALL)).is_err(), "{property}={argument}");
                    }
                }
                let wrapper = format!("[Service]\nEnvironment=BIN={INSTALL}\nExecStart=/bin/sh -c 'exec $$BIN'\n");
                assert!(parse_source("owned.service", wrapper.as_bytes(), Path::new(INSTALL)).is_err());
            }

            #[test]
            fn inventory_commands_refuse_templates_before_command_parsing() {
                for name in ["owned@.service", "owned@blue.service"] {
                    for source in [b"[Service]\n".as_slice(), b"[Service]\nExecStart=/owned/missing\n".as_slice()] {
                        assert!(parse_source(name, source, Path::new(INSTALL)).is_err());
                    }
                }
            }

            #[test]
            fn inventory_commands_refuse_prefixes_escapes_and_compound_syntax() {
                for command in [
                    format!("-{INSTALL}"), format!("@{INSTALL}"), format!(":{INSTALL}"),
                    format!("+{INSTALL}"), format!("!{INSTALL}"), format!("!!{INSTALL}"),
                    format!("{INSTALL} escaped\\ space"), format!("{INSTALL} 'unterminated"),
                    format!("{INSTALL} \"unterminated"), format!("{INSTALL} ; {INSTALL}"),
                    format!("{INSTALL} 'quoted;separator'"), format!("{INSTALL} \\\n --name owned"),
                ] {
                    let source = format!("[Service]\nExecStart={command}\n");
                    assert!(parse_source("owned.service", source.as_bytes(), Path::new(INSTALL)).is_err(), "{command}");
                }
            }

            #[test]
            fn inventory_commands_refuse_ambiguous_or_invalid_raw_source() {
                for source in [
                    b"[Service\n".as_slice(), b"[[Service]]\n".as_slice(),
                    b"[]\n".as_slice(), b"ExecStart=/owned/bin/x0xd\n".as_slice(),
                    b"[Service]\nnot-an-assignment\n".as_slice(),
                    b"[Service]\n=missing-key\n".as_slice(), b"[Service]\nExec Start=\n".as_slice(),
                    b"[Service]\nExecUnknown=\n".as_slice(),
                    b"[Service]\n# invalid\0comment\n".as_slice(),
                    b"[Service]\n# invalid\xffcomment\n".as_slice(),
                ] {
                    assert!(parse_source("owned.service", source, Path::new(INSTALL)).is_err());
                }
                assert!(parse_command(Path::new(INSTALL), &argv(&[INSTALL, "bad\0argument"]), Path::new(INSTALL)).is_err());
            }

            #[test]
            fn inventory_commands_bound_raw_source_at_one_mib() {
                let mut source = format!("[Service]\nExecStart={INSTALL}\n#").into_bytes();
                source.resize(1_048_576, b'x');
                assert_eq!(parse_source("owned.service", &source, Path::new(INSTALL)).unwrap().len(), 1);
                source.push(b'x');
                assert!(parse_source("owned.service", &source, Path::new(INSTALL)).is_err());
            }

            #[test]
            fn inventory_commands_bound_total_argument_bytes_and_argument_count() {
                let mut arguments = vec![INSTALL.to_owned(), "x".repeat(1_048_576 - INSTALL.len())];
                assert_eq!(parse_command(Path::new(INSTALL), &arguments, Path::new(INSTALL)).unwrap().argv, arguments);
                arguments[1].push('x');
                assert!(parse_command(Path::new(INSTALL), &arguments, Path::new(INSTALL)).is_err());
                let mut arguments = vec![INSTALL.to_owned()];
                arguments.extend(std::iter::repeat_n("x".to_owned(), 4095));
                assert_eq!(parse_command(Path::new(INSTALL), &arguments, Path::new(INSTALL)).unwrap().argv.len(), 4096);
                arguments.push("x".to_owned());
                assert!(parse_command(Path::new(INSTALL), &arguments, Path::new(INSTALL)).is_err());
            }

            #[test]
            fn inventory_commands_bound_retained_command_count() {
                let mut source = "[Service]\n".to_owned();
                for _ in 0..4096 {
                    source.push_str(&format!("ExecStart={INSTALL}\n"));
                }
                source.push_str("ExecStart=\n");
                assert_eq!(parse_source("owned.service", source.as_bytes(), Path::new(INSTALL)).unwrap().len(), 4096);
                source.push_str(&format!("ExecStart={INSTALL}\n"));
                assert!(parse_source("owned.service", source.as_bytes(), Path::new(INSTALL)).is_err());
            }
        }
    };
}
