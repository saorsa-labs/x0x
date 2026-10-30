// Invoke inside the private inventory_accounts module. The standalone integration
// target has no tests. These supplied-byte controls prove no source capture,
// NSS discovery, account freshness, or complete host inventory.
#[allow(unused_macros)]
macro_rules! inventory_accounts_regression_tests {
    () => {
        #[cfg(unix)]
        mod inventory_accounts_regressions {
            use super::AccountTable;
            use std::collections::BTreeSet;
            use std::path::Path;

            const POLICY: &[u8] = b"passwd: files\ngroup: files\nhosts: files dns\n";
            const PASSWD: &[u8] = b"root:x:0:0:root:/root:/bin/sh\nalice:x:12345:23456:fixture:/owned/alice:/bin/false\n";
            const GROUP: &[u8] = b"root:x:0:\nfixture:x:23456:alice\n";

            fn table() -> AccountTable {
                AccountTable::parse(POLICY, PASSWD, GROUP).unwrap()
            }

            fn assert_redacted(value: &impl std::fmt::Debug, label: &str) {
                let expected = format!("{label}(<redacted>)");
                assert_eq!(format!("{value:?}"), expected);
                assert_eq!(format!("{value:#?}"), expected);
                assert_eq!(format!("{:?}", Some(value)), format!("Some({expected})"));
                assert_eq!(format!("{:#?}", [value]), format!("[\n    {expected},\n]"));
            }

            #[test]
            fn account_debug_redacts_ids_and_home() {
                let accounts = table();
                assert_redacted(accounts.by_uid(12345).unwrap(), "Account");
            }

            #[test]
            fn account_table_debug_redacts_names_groups_and_digest() {
                assert_redacted(&table(), "AccountTable");
            }

            #[test]
            fn inventory_accounts_resolve_only_the_bound_files_table() {
                let table = table();
                assert_eq!(table.uids().collect::<BTreeSet<_>>(), BTreeSet::from([0, 12345]));
                for name in ["alice", "12345", ""] {
                    let account = table.resolve_user(name, 12345).unwrap();
                    assert_eq!((account.uid, account.gid), (12345, 23456));
                    assert_eq!(account.home, Path::new("/owned/alice"));
                }
                assert_eq!(table.by_uid(0).unwrap().home, Path::new("/root"));
                for name in ["fixture", "23456", ""] {
                    assert_eq!(table.resolve_group(name, 23456).unwrap(), 23456);
                }
                for unknown in ["nobody", "unknown-fixture-user", "54321", "4294967295"] {
                    assert!(table.resolve_user(unknown, 0).is_err(), "{unknown}");
                    assert!(table.resolve_group(unknown, 0).is_err(), "{unknown}");
                }
                assert!(table.by_uid(54321).is_err());
                assert!(table.resolve_user("", 54321).is_err());
                assert!(table.resolve_group("", 54321).is_err());
            }

            #[test]
            fn inventory_accounts_refuse_unknown_nss_authority_before_lookup() {
                for policy in [
                    "passwd: files ldap\ngroup: files\n",
                    "passwd: compat\ngroup: files\n",
                    "passwd: files\ngroup: files sss\n",
                    "passwd: files systemd\ngroup: files\n",
                    "passwd: files [NOTFOUND=return]\ngroup: files\n",
                    "passwd: files;\ngroup: files\n",
                    "passwd: files\ngroup: files ;\n",
                    "passwd: files[NOTFOUND=return]\ngroup: files\n",
                    "passwd: files\ngroup: files\ninitgroups: files [SUCCESS=continue]\n",
                    "passwd: files\ngroup: files\ninitgroups: files ldap\n",
                    "passwd: files\ngroup:\n",
                ] {
                    assert!(AccountTable::parse(policy.as_bytes(), PASSWD, GROUP).is_err(), "{policy}");
                }
                assert!(AccountTable::parse(POLICY, PASSWD, GROUP).is_ok());
                assert!(AccountTable::parse(b"passwd: files\ngroup: files\ninitgroups: files\n", PASSWD, GROUP).is_ok());
            }

            #[test]
            fn inventory_accounts_refuse_hidden_optional_database_authority() {
                let base = "passwd: files\ngroup: files\n";
                // glibc identifies the database at the first C whitespace or
                // colon. A later colon must not hide an initgroups policy.
                for separator in [' ', '\t', '\x0b', '\x0c', '\r'] {
                    let policy = format!("{base}initgroups{separator}extra: files\n");
                    assert!(AccountTable::parse(policy.as_bytes(), PASSWD, GROUP).is_err(), "{policy:?}");
                }
                // The local supported subset requires an explicit colon; it
                // must also refuse, not ignore, a colon-free optional row.
                assert!(AccountTable::parse(format!("{base}initgroups files\n").as_bytes(), PASSWD, GROUP).is_err());
                assert!(AccountTable::parse(format!("{base}initgroups: files\n").as_bytes(), PASSWD, GROUP).is_ok());
            }

            #[test]
            fn inventory_accounts_refuse_unicode_normalized_policy_keys() {
                for database in ["passwd", "group", "initgroups"] {
                    let other = match database {
                        "passwd" => "group: files\n",
                        "group" => "passwd: files\n",
                        _ => "passwd: files\ngroup: files\n",
                    };
                    for space in ['\u{a0}', '\u{2003}', '\u{202f}', '\u{3000}'] {
                        for policy in [format!("{other}{space}{database}: files\n"), format!("{other}{database}{space}: files\n")] {
                            assert!(AccountTable::parse(policy.as_bytes(), PASSWD, GROUP).is_err(), "{policy:?}");
                        }
                    }
                }
            }

            #[test]
            fn inventory_accounts_refuse_unicode_normalized_source_names() {
                for database in ["passwd", "group", "initgroups"] {
                    let other = match database {
                        "passwd" => "group: files\n",
                        "group" => "passwd: files\n",
                        _ => "passwd: files\ngroup: files\n",
                    };
                    for space in ['\u{a0}', '\u{2003}', '\u{202f}', '\u{3000}'] {
                        for policy in [format!("{other}{database}: {space}files\n"), format!("{other}{database}: files{space}\n")] {
                            assert!(AccountTable::parse(policy.as_bytes(), PASSWD, GROUP).is_err(), "{policy:?}");
                        }
                    }
                }
            }

            #[test]
            fn inventory_accounts_accept_explicit_c_whitespace_in_policy() {
                let policy = b" \t\x0bpasswd \x0c: \rfiles\x0b\n\x0cgroup\t:\x0bfiles \r\n";
                let parsed = AccountTable::parse(policy, PASSWD, GROUP).unwrap();
                assert_eq!(parsed.by_uid(12345).unwrap(), table().by_uid(12345).unwrap());
            }

            #[test]
            fn inventory_accounts_preserve_unicode_data_and_ignored_comments() {
                let passwd = std::str::from_utf8(PASSWD).unwrap().replace("fixture:/owned/alice", "Alíce\u{a0}:/owned/équipe\u{a0}");
                let policy = "# données\u{a0}\npasswd: files # privé\u{2003}\ngroup: files # groupe\u{3000}\n";
                let group = format!("{}# membres\u{202f}\n", std::str::from_utf8(GROUP).unwrap());
                let base = AccountTable::parse(POLICY, passwd.as_bytes(), GROUP).unwrap();
                let changed = AccountTable::parse(policy.as_bytes(), passwd.as_bytes(), group.as_bytes()).unwrap();
                assert_eq!(changed.by_uid(12345).unwrap().home, Path::new("/owned/équipe\u{a0}"));
                assert_eq!(base.by_uid(12345).unwrap(), changed.by_uid(12345).unwrap());
                assert_eq!(changed.resolve_group("fixture", 0).unwrap(), 23456);
                assert_ne!(base.digest, changed.digest);
            }

            #[test]
            fn inventory_accounts_refuse_missing_duplicate_or_ambiguous_policy() {
                for policy in [
                    "group: files\n", "passwd: files\n", "",
                    "passwd: files\npasswd: files\ngroup: files\n",
                    "passwd: files\ngroup: files\ngroup: files\n",
                    "passwd: files\\\n ldap\ngroup: files\n",
                    "passwd: files\ngroup: files\npasswd_compat: nis\n",
                    "passwd files\ngroup: files\n",
                ] {
                    assert!(AccountTable::parse(policy.as_bytes(), PASSWD, GROUP).is_err(), "{policy}");
                }
            }

            #[test]
            fn inventory_accounts_refuse_incomplete_or_ambiguous_rows() {
                let passwd = std::str::from_utf8(PASSWD).unwrap();
                for passwd in [
                    String::new(), passwd.replace(":/root:", ":relative:"),
                    format!("{passwd}alias:x:0:0::/alias:/bin/sh\n"),
                    format!("{passwd}root:x:2:0::/other:/bin/sh\n"),
                    passwd.replace("12345:23456:", "12345:999:"),
                    format!("{passwd}+::::::\n"),
                    format!("{passwd}other:x:4294967295:0::/other:/bin/sh\n"),
                    passwd.replace("root:x:0:0:", "root:x:-1:0:"),
                    passwd.replace("alice:x:12345:", "12345:x:12345:"),
                ] {
                    assert!(AccountTable::parse(POLICY, passwd.as_bytes(), GROUP).is_err());
                }
                let group = std::str::from_utf8(GROUP).unwrap();
                for group in [
                    String::new(), group.replace(":alice", ":missing"),
                    format!("{group}alias:x:23456:\n"), format!("{group}fixture:x:999:\n"),
                    format!("{group}+:::\n"), format!("{group}other:x:4294967295:\n"),
                    group.replace("root:x:0:", "root:x:-1:"),
                ] {
                    assert!(AccountTable::parse(POLICY, PASSWD, group.as_bytes()).is_err());
                }
            }

            #[test]
            fn inventory_accounts_bind_each_exact_source_in_the_digest() {
                let original = table();
                assert_eq!(original, table());
                // Each mutation is a valid, semantically ignored field or comment.
                // Lookup equality plus changed digests proves exact source binding.
                for index in 0..3 {
                    let mut sources = [POLICY.to_vec(), PASSWD.to_vec(), GROUP.to_vec()];
                    sources[index].extend_from_slice(b"# different source bytes\n");
                    let changed = AccountTable::parse(&sources[0], &sources[1], &sources[2]).unwrap();
                    assert_eq!(original.by_uid(12345).unwrap(), changed.by_uid(12345).unwrap());
                    assert_eq!(original.resolve_group("fixture", 0).unwrap(), changed.resolve_group("fixture", 0).unwrap());
                    assert_ne!(original.digest, changed.digest, "source {index}");
                }
                let changed = AccountTable::parse(POLICY, &String::from_utf8(PASSWD.to_vec()).unwrap().replace("fixture:", "changed:").into_bytes(), GROUP).unwrap();
                assert_eq!(original.by_uid(12345).unwrap(), changed.by_uid(12345).unwrap());
                assert_ne!(original.digest, changed.digest);
            }

            #[test]
            fn inventory_accounts_refuse_invalid_encoding_in_each_source() {
                for index in 0..3 {
                    for invalid in [0, 0xff] {
                        let mut sources = [POLICY.to_vec(), PASSWD.to_vec(), GROUP.to_vec()];
                        sources[index].extend_from_slice(&[b'#', invalid, b'\n']);
                        assert!(AccountTable::parse(&sources[0], &sources[1], &sources[2]).is_err(), "source {index}, byte {invalid}");
                    }
                }
            }

            #[test]
            fn inventory_accounts_enforce_one_mib_per_source() {
                for index in 0..3 {
                    let mut sources = [POLICY.to_vec(), PASSWD.to_vec(), GROUP.to_vec()];
                    sources[index].push(b'#');
                    sources[index].resize(1_048_576, b'x');
                    let at_limit = AccountTable::parse(&sources[0], &sources[1], &sources[2]).unwrap();
                    assert_eq!(at_limit.by_uid(12345).unwrap(), table().by_uid(12345).unwrap());
                    sources[index].push(b'x');
                    assert!(AccountTable::parse(&sources[0], &sources[1], &sources[2]).is_err(), "source {index}");
                }
            }

            #[test]
            fn inventory_accounts_enforce_4096_user_rows() {
                let mut passwd = "root:x:0:0::/root:/bin/sh\n".to_owned();
                for uid in 1..4096 {
                    passwd.push_str(&format!("user{uid}:x:{uid}:0::/owned/{uid}:/bin/false\n"));
                }
                let group = b"root:x:0:\n";
                let at_limit = AccountTable::parse(POLICY, passwd.as_bytes(), group).unwrap();
                assert_eq!(at_limit.uids().count(), 4096);
                assert_eq!(at_limit.by_uid(4095).unwrap().home, Path::new("/owned/4095"));
                passwd.push_str("overflow:x:4096:0::/owned/overflow:/bin/false\n");
                assert!(AccountTable::parse(POLICY, passwd.as_bytes(), group).is_err());
            }

            #[test]
            fn inventory_accounts_enforce_4096_group_rows() {
                let passwd = b"root:x:0:0::/root:/bin/sh\n";
                let mut group = "root:x:0:\n".to_owned();
                for gid in 1..4096 {
                    group.push_str(&format!("group{gid}:x:{gid}:\n"));
                }
                let at_limit = AccountTable::parse(POLICY, passwd, group.as_bytes()).unwrap();
                assert_eq!(at_limit.resolve_group("group4095", 0).unwrap(), 4095);
                group.push_str("overflow:x:4096:\n");
                assert!(AccountTable::parse(POLICY, passwd, group.as_bytes()).is_err());
            }
        }
    };
}
