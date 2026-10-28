// Inert controls: supplied strings/bytes/paths only; no process environment or I/O.
#[allow(unused_macros)]
macro_rules! inventory_roots_tests {
    () => {
        mod inventory_roots_regressions {
            use super::*;
            fn argv(args: &[&str]) -> Vec<String> {
                std::iter::once("/opt/x0xd").chain(args.iter().copied()).map(str::to_owned).collect()
            }
            fn env(values: &[(&str, &str)]) -> BTreeMap<String, String> {
                values.iter().map(|(k,v)| (k.to_string(),v.to_string())).collect()
            }
            fn selection(platform: Platform, args: &[&str], values: &[(&str, &str)]) -> Selection {
                select(platform, &argv(args), Path::new("/work"), &env(values), Some(Path::new("/account"))).unwrap()
            }
            fn roots(s: &Selection, text: &str) -> LexicalRoots { s.resolve(Some(text.as_bytes())).unwrap() }
            #[test]
            fn default_linux_roots_use_observed_account_only() {
                let s = selection(Platform::Linux, &[], &[]);
                assert_eq!(s.config_path, Path::new("/account/.config/x0x/config.toml"));
                let r = s.resolve(None).unwrap();
                assert_eq!(r.data, Path::new("/account/.local/share/x0x"));
                assert_eq!(r.identity, Path::new("/account/.x0x"));
                assert_eq!(r.name, None);
                assert!(select(Platform::Linux, &argv(&[]), Path::new("/work"), &env(&[]), None).is_err());
            }
            #[test]
            fn home_override_and_empty_home_fallback() {
                let s = selection(Platform::Linux, &[], &[("HOME", "/participant")]);
                assert_eq!(s.resolve(None).unwrap().identity, Path::new("/participant/.x0x"));
                let s = selection(Platform::Linux, &[], &[("HOME", "")]);
                assert_eq!(s.resolve(None).unwrap().identity, Path::new("/account/.x0x"));
            }
            #[test]
            fn linux_xdg_defaults_and_relative_values() {
                let s = selection(Platform::Linux, &["--name", "Alice-2"], &[("XDG_CONFIG_HOME", "/cfg"), ("XDG_DATA_HOME", "/data")]);
                assert_eq!(s.config_path, Path::new("/cfg/x0x-Alice-2/config.toml"));
                assert_eq!(s.resolve(None).unwrap().data, Path::new("/data/x0x-Alice-2"));
                for value in ["", "relative", "../relative"] {
                    let s = selection(Platform::Linux, &[], &[("XDG_CONFIG_HOME", value), ("XDG_DATA_HOME", value)]);
                    assert_eq!(s.config_path, Path::new("/account/.config/x0x/config.toml"));
                    assert_eq!(s.resolve(None).unwrap().data, Path::new("/account/.local/share/x0x"));
                }
            }
            #[test]
            fn macos_ignores_xdg_and_uses_application_support() {
                let s = selection(Platform::Macos, &["--name", "alice"], &[("HOME", "/Users/alice"), ("XDG_CONFIG_HOME", "/wrong"), ("XDG_DATA_HOME", "/wrong")]);
                assert_eq!(s.config_path, Path::new("/Users/alice/Library/Application Support/x0x-alice/config.toml"));
                let r = s.resolve(None).unwrap();
                assert_eq!(r.data, Path::new("/Users/alice/Library/Application Support/x0x-alice"));
                assert_eq!(r.identity, Path::new("/Users/alice/.x0x-alice"));
            }
            #[test]
            fn config_name_changes_roots_but_never_selected_config() {
                let s = selection(Platform::Linux, &[], &[]);
                let r = roots(&s, "instance_name = 'config-name'");
                assert_eq!(r.name.as_deref(), Some("config-name"));
                assert_eq!(r.data, Path::new("/account/.local/share/x0x-config-name"));
                assert_eq!(r.identity, Path::new("/account/.x0x-config-name"));
                assert_eq!(s.config_path, Path::new("/account/.config/x0x/config.toml"));
            }
            #[test]
            fn cli_name_wins_over_config_name() {
                let s = selection(Platform::Linux, &["--name", "cli"], &[]);
                let r = roots(&s, "instance_name = '../ignored'");
                assert_eq!(r.name.as_deref(), Some("cli"));
                assert_eq!(r.data, Path::new("/account/.local/share/x0x-cli"));
                assert_eq!(r.identity, Path::new("/account/.x0x-cli"));
                assert!(s.resolve(Some(b"instance_name = 7")).is_err());
            }
            #[test]
            fn explicit_config_is_relative_to_cwd_and_requires_bytes() {
                let s = selection(Platform::Linux, &["--config", "cfg/custom.toml", "--name", "alice"], &[]);
                assert_eq!(s.config_path, Path::new("/work/cfg/custom.toml"));
                assert!(s.resolve(None).is_err());
                assert!(s.resolve(Some(b"")).is_ok());
                let s = selection(Platform::Linux, &["--config", "/etc/other.toml"], &[]);
                assert_eq!(s.config_path, Path::new("/etc/other.toml"));
            }
            #[test]
            fn explicit_default_data_value_is_still_named() {
                let s = selection(Platform::Linux, &["--name", "a"], &[]);
                assert_eq!(roots(&s, "data_dir = '/account/.local/share/x0x'").data, Path::new("/account/.local/share/x0x-a"));
                assert_eq!(roots(&s, "data_dir = '/custom/data'").data, Path::new("/custom/data"));
            }
            #[test]
            fn relative_roots_use_cwd_not_config_parent() {
                let s = selection(Platform::Linux, &["--config", "/config/daemon.toml"], &[]);
                let r = roots(&s, "data_dir = 'state'\nidentity_dir = 'keys'");
                assert_eq!(r.data, Path::new("/work/state"));
                assert_eq!(r.identity, Path::new("/work/keys"));
            }
            #[test]
            fn identity_override_uses_sibling_for_named_instance() {
                let s = selection(Platform::Linux, &[], &[("X0X_HOME", "/vault/default")]);
                assert_eq!(s.resolve(None).unwrap().identity, Path::new("/vault/default"));
                assert_eq!(roots(&s, "instance_name = 'a'").identity, Path::new("/vault/.x0x-a"));
                assert_eq!(roots(&s, "instance_name = 'a'\nidentity_dir = '/keys/custom'").identity, Path::new("/keys/custom"));
                let s = selection(Platform::Linux, &["--name", "a"], &[("X0X_HOME", "relative")]);
                assert_eq!(s.resolve(None).unwrap().identity, Path::new("/work/.x0x-a"));
                let s = selection(Platform::Linux, &[], &[("X0X_HOME", "")]);
                assert_eq!(s.resolve(None).unwrap().identity, Path::new("/account/.x0x"));
                let s = selection(Platform::Linux, &["--name", "a"], &[("X0X_HOME", "/")]);
                assert!(s.resolve(None).is_err());
            }
            #[test]
            fn nested_root_keys_remain_ignored_as_in_daemon_config() {
                let s = selection(Platform::Linux, &[], &[]);
                assert_eq!(roots(&s, "[history]\ndata_dir = '/wrong'\nidentity_dir = '/wrong'\ninstance_name = 'wrong'"), s.resolve(None).unwrap());
            }
            #[test]
            fn ambiguous_or_malformed_root_arguments_refuse() {
                for args in [vec!["--name"], vec!["--name", ""], vec!["--config"], vec!["--config", ""], vec!["--name=a"], vec!["--config=x"], vec!["--name", "a", "--name", "b"], vec!["--config", "a", "--config", "b"]] {
                    assert!(select(Platform::Linux, &argv(&args), Path::new("/work"), &env(&[("HOME", "/home/a")]), None).is_err(), "{args:?}");
                }
                for bad in [vec![], vec!["".into()], vec!["--name".into(), "a".into()], vec!["x0xd".into(), "bad\0arg".into()]] {
                    assert!(select(Platform::Linux, &bad, Path::new("/work"), &env(&[("HOME", "/home/a")]), None).is_err());
                }
            }
            #[test]
            fn invalid_names_and_root_field_types_refuse() {
                let s = selection(Platform::Linux, &[], &[]);
                for name in ["", "../a", "a_b", "a/b", "-a", "é", &"a".repeat(65)] {
                    assert!(s.resolve(Some(format!("instance_name = '{name}'").as_bytes())).is_err());
                    assert!(select(Platform::Linux, &argv(&["--name", name]), Path::new("/work"), &env(&[]), Some(Path::new("/home/a"))).is_err());
                }
                assert!(s.resolve(Some(format!("instance_name = '{}'", "a".repeat(64)).as_bytes())).is_ok());
                for bad in ["data_dir = 1", "identity_dir = []", "instance_name = false", "data_dir = 'a'\ndata_dir = 'b'", "data_dir = "] {
                    assert!(s.resolve(Some(bad.as_bytes())).is_err());
                }
            }
            #[test]
            fn paths_refuse_empty_nul_and_parent_traversal() {
                let s = selection(Platform::Linux, &[], &[]);
                for field in ["data_dir", "identity_dir"] {
                    for value in ["", "../outside", "/data/../outside"] {
                        assert!(s.resolve(Some(format!("{field} = '{value}'").as_bytes())).is_err());
                    }
                    assert!(s.resolve(Some(format!("{field} = \"bad\\u0000path\"").as_bytes())).is_err());
                }
                for path in ["relative", "/work/../elsewhere"] {
                    assert!(select(Platform::Linux, &argv(&[]), Path::new(path), &env(&[]), Some(Path::new("/home/a"))).is_err());
                }
                for (key, value) in [("HOME", "relative"), ("HOME", "/a/../b"), ("XDG_DATA_HOME", "/a/../b"), ("XDG_CONFIG_HOME", "/a/../b"), ("X0X_HOME", "../b"), ("HOME", "/private\0value")] {
                    assert!(select(Platform::Linux, &argv(&[]), Path::new("/work"), &env(&[(key,value)]), Some(Path::new("/account"))).is_err());
                }
            }
            #[test]
            fn config_byte_limit_utf8_and_diagnostics() {
                let s = selection(Platform::Linux, &[], &[]);
                let mut bytes = vec![b' '; MAX_BYTES]; bytes[0] = b'#';
                assert!(s.resolve(Some(&bytes)).is_ok());
                bytes.push(b' ');
                assert!(s.resolve(Some(&bytes)).is_err());
                assert!(s.resolve(Some(b"\xff")).is_err());
                let err = s.resolve(Some(b"identity_dir = '/secret/../secret' ")).unwrap_err();
                assert!(!err.to_string().contains("secret"));
                let err = s.resolve(Some(b"data_dir = PRIVATE_TOKEN")).unwrap_err();
                assert!(!err.to_string().contains("PRIVATE_TOKEN"));
            }
            #[test]
            fn non_utf8_account_home_refuses_daemon_config_fallback() {
                use std::ffi::OsStr;
                use std::os::unix::ffi::OsStrExt;
                let home = Path::new(OsStr::from_bytes(b"/account/\xff"));
                assert!(select(Platform::Linux, &argv(&[]), Path::new("/work"), &env(&[]), Some(home)).is_err());
                // A supplied UTF-8 HOME takes precedence over the account fallback.
                assert!(select(Platform::Linux, &argv(&[]), Path::new("/work"), &env(&[("HOME", "/participant")]), Some(home)).is_ok());
            }
            #[test]
            fn joining_paths_cannot_exceed_path_bound() {
                let cwd = PathBuf::from(format!("/{}", "a".repeat(MAX_BYTES - 1)));
                assert!(checked_path(&cwd, Path::new("/")).is_ok());
                assert!(checked_path(Path::new("b"), &cwd).is_err());
                assert!(checked_path(Path::new(&"a".repeat(MAX_BYTES + 1)), Path::new("/")).is_err());
            }
            #[test]
            fn argv_byte_and_count_bounds_are_inclusive() {
                let e = env(&[("HOME", "/participant")]);
                let check = |a: &[String]| select(Platform::Linux, a, Path::new("/work"), &e, None);
                let mut a = vec!["x0xd".into(), "x".repeat(MAX_BYTES - 6)];
                assert!(check(&a).is_ok()); a[1].push('x'); assert!(check(&a).is_err());
                let mut a = vec![String::new(); MAX_ARGS]; a[0] = "x0xd".into();
                assert!(check(&a).is_ok()); a.push(String::new()); assert!(check(&a).is_err());
            }
        }
    }
}
