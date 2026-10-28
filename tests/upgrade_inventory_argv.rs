// Inert raw-byte controls: no process, file, daemon, network or environment I/O.
#[allow(unused_macros)]
macro_rules! inventory_argv_regression_tests {
    () => {
        mod inventory_argv_regressions {
            use super::{parse_cmdline, parse_root_environment};
            use std::io::ErrorKind;

            #[test]
            fn argv_keeps_boundaries_empty_arguments_and_opaque_text() {
                let raw = "custom title\0--name\0\0a b\0é\0tab\tline\n\0x=y\0\0";
                assert_eq!(
                    parse_cmdline(raw.as_bytes()).unwrap(),
                    ["custom title", "--name", "", "a b", "é", "tab\tline\n", "x=y", ""]
                );
                assert_eq!(parse_cmdline(b"worker\0").unwrap(), ["worker"]);
            }

            #[test]
            fn argv_refuses_missing_argv0_and_final_terminator() {
                for raw in [b"".as_slice(), b"\0", b"\0worker\0", b"worker", b"worker\0last"] {
                    assert_eq!(parse_cmdline(raw).unwrap_err().kind(), ErrorKind::InvalidData);
                }
            }

            #[test]
            fn argv_refuses_invalid_utf8_in_every_position() {
                for raw in [b"\xff\0".as_slice(), b"worker\0\xff\0"] {
                    let error = parse_cmdline(raw).unwrap_err();
                    assert_eq!(error.kind(), ErrorKind::InvalidData);
                    assert_eq!(error.to_string(), "process argument is not UTF-8");
                }
            }

            #[test]
            fn argv_byte_bound_is_inclusive() {
                let mut raw = vec![b'x'; 1_048_575];
                raw.push(0);
                assert_eq!(parse_cmdline(&raw).unwrap()[0].len(), 1_048_575);
                raw.insert(0, b'x');
                assert!(parse_cmdline(&raw).is_err());
            }

            #[test]
            fn argv_entry_bound_counts_empty_arguments() {
                let mut raw = b"worker\0".to_vec();
                raw.extend(std::iter::repeat_n(0, 16_383));
                let args = parse_cmdline(&raw).unwrap();
                assert_eq!(args.len(), 16_384);
                assert!(args[1..].iter().all(String::is_empty));
                raw.push(0);
                assert!(parse_cmdline(&raw).is_err());
            }

            #[test]
            fn environment_selects_only_exact_root_keys_without_normalization() {
                let raw = "HOME=/home/é\0XDG_CONFIG_HOME=relative\0XDG_DATA_HOME=\0X0X_HOME=a=b\0home=bad\0 HOME=bad\0HOME_EXTRA=bad\0PATH=secret\0";
                let env = parse_root_environment(raw.as_bytes()).unwrap();
                assert_eq!(env.len(), 4);
                assert_eq!(env["HOME"], "/home/é");
                assert_eq!(env["XDG_CONFIG_HOME"], "relative");
                assert_eq!(env["XDG_DATA_HOME"], "");
                assert_eq!(env["X0X_HOME"], "a=b");
                assert_eq!(parse_root_environment(b"HOME= /a\t\n \0").unwrap()["HOME"], " /a\t\n ");
            }

            #[test]
            fn environment_allows_optional_final_nul_and_empty_input() {
                let expected = parse_root_environment(b"HOME=/a\0X0X_HOME=/b\0").unwrap();
                assert_eq!(parse_root_environment(b"HOME=/a\0X0X_HOME=/b").unwrap(), expected);
                for raw in [b"".as_slice(), b"\0", b"PATH=ignored\0"] {
                    assert!(parse_root_environment(raw).unwrap().is_empty());
                }
                assert_eq!(parse_root_environment(b"HOME=").unwrap()["HOME"], "");
            }

            #[test]
            fn environment_refuses_equal_and_conflicting_selected_duplicates() {
                for key in ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "X0X_HOME"] {
                    for second in ["/one", "/two", ""] {
                        for suffix in ["", "\0"] {
                            let raw = format!("{key}=/one\0{key}={second}{suffix}");
                            assert!(parse_root_environment(raw.as_bytes()).is_err());
                        }
                    }
                }
            }

            #[test]
            fn environment_refuses_malformed_selected_entries_only() {
                for key in ["HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "X0X_HOME"] {
                    assert!(parse_root_environment(key.as_bytes()).is_err());
                    let raw = format!("{key}=private-value").into_bytes();
                    let mut raw = raw;
                    raw.extend_from_slice(b"\xff\0");
                    let error = parse_root_environment(&raw).unwrap_err();
                    assert_eq!(error.kind(), ErrorKind::InvalidData);
                    assert_eq!(error.to_string(), "root environment value is not UTF-8");
                }
                let env = parse_root_environment(b"\xff=\xfe\0UNRELATED\0=ignored\0\0HOME=/a\0").unwrap();
                assert_eq!(env.len(), 1);
                assert_eq!(env["HOME"], "/a");
            }

            #[test]
            fn environment_byte_bound_includes_ignored_data() {
                let mut raw = b"IGNORED=".to_vec();
                raw.resize(1_048_576, b'x');
                assert!(parse_root_environment(&raw).unwrap().is_empty());
                raw.push(0);
                assert!(parse_root_environment(&raw).is_err());
            }

            #[test]
            fn environment_entry_bound_includes_ignored_and_empty_entries() {
                for entry in [b"X=ignored\0".as_slice(), b"\0"] {
                    let mut raw = entry.repeat(16_384);
                    assert!(parse_root_environment(&raw).unwrap().is_empty());
                    raw.extend_from_slice(entry);
                    assert!(parse_root_environment(&raw).is_err());
                }
            }

            #[test]
            fn diagnostics_do_not_echo_selected_values() {
                let error = parse_root_environment(b"HOME=private-a\0HOME=private-b\0").unwrap_err();
                assert_eq!(error.to_string(), "duplicate root environment key");
                let error = parse_cmdline(b"private-unterminated").unwrap_err();
                assert_eq!(error.to_string(), "process argv lacks final NUL");
            }
        }
    };
}
