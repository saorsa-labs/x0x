// Pure raw-byte controls. No process, filesystem, daemon or network reads.
#[allow(unused_macros)]
macro_rules! inventory_procfs_regression_tests {
    () => {
        mod inventory_procfs_regressions {
            use super::{check_mountinfo, parse_credentials, parse_stat};
            const MOUNT: &[u8] =
                b"27 23 0:5 / /proc rw,nosuid,nodev,noexec,relatime - proc proc rw\n";
            const STATUS: &[u8] =
                b"Name:\tworker\nUid:\t1000\t1000\t1000\t1000\nGid:\t100\t100\t100\t100\n";
            fn stat(comm: &[u8]) -> Vec<u8> {
                let mut s = b"123 (".to_vec();
                s.extend_from_slice(comm);
                // Fields 3..22: flags at index6, starttime at index19.
                s.extend_from_slice(b") S 1 2 3 0 -1 4194304 0 0 0 0 10 11 0 0 20 0 1 0 987654\n");
                s
            }
            #[test]
            fn stat_preserves_pid_flags_and_start_with_opaque_comm() {
                for comm in [b"worker".as_slice(), b") weird (name)\n", b"\xff\xfe"] {
                    let s = parse_stat(&stat(comm)).unwrap();
                    assert_eq!(s.pid, 123);
                    assert_eq!(s.state, b'S');
                    assert_eq!(s.flags, 4194304);
                    assert_eq!(s.start_ticks, 987654);
                }
            }
            #[test]
            fn stat_refuses_malformed_identity_or_truncated_fields() {
                let normal = String::from_utf8(stat(b"worker")).unwrap();
                for s in [
                    normal.replacen("123 ", "0 ", 1),
                    normal.replacen("123 ", "+123 ", 1),
                    normal.replacen("123 ", "4294967296 ", 1),
                    normal.replace(") S ", ") SS "),
                    normal.replace(") S ", ") Q "),
                    normal.replace("987654", "-1"),
                    normal.replace("4194304", "18446744073709551616"),
                    normal.replace("987654", ""),
                    normal.replace(" (", "("),
                    normal.replace(") S", ")S"),
                    "123 worker) S 1 2".into(),
                ] {
                    assert!(parse_stat(s.as_bytes()).is_err(), "{s:?}");
                }
            }
            #[test]
            fn credentials_bind_all_four_ids_without_account_lookup() {
                let ids = parse_credentials(STATUS).unwrap();
                assert_eq!(ids.uid, 1000);
                assert_eq!(ids.gid, 100);
                let mut opaque = b"Name:\t\xff\n".to_vec();
                opaque.extend_from_slice(STATUS);
                assert_eq!(parse_credentials(&opaque).unwrap(), ids);
            }
            #[test]
            fn credentials_refuse_missing_duplicate_mixed_or_overflow_ids() {
                for bad in [
                    b"Uid: 1 1 1 1\n".as_slice(),
                    b"Gid: 1 1 1 1\n",
                    b"Uid: 1 1 2 1\nGid: 1 1 1 1\n",
                    b"Uid: 1 1 1 1\nGid: 1 2 1 1\n",
                    b"Uid: 1 1 1\nGid: 1 1 1 1\n",
                    b"Uid: +1 +1 +1 +1\nGid: 1 1 1 1\n",
                    b"Uid: 4294967296 4294967296 4294967296 4294967296\nGid: 1 1 1 1\n",
                    b"Uid: 1 1 1 1\nGid: 1 1 1 1\nUid: 1 1 1 1\n",
                    b"Uid: 1 1 1 1\nGid: 1 1 1 1\nGid: 1 1 1 1\n",
                ] {
                    assert!(parse_credentials(bad).is_err(), "{bad:?}");
                }
            }
            #[test]
            fn mountinfo_accepts_explicit_unfiltered_root_and_opaque_other_paths() {
                check_mountinfo(MOUNT).unwrap();
                for option in ["hidepid=0", "hidepid=off,gid=1234"] {
                    let s = String::from_utf8(MOUNT.to_vec()).unwrap().replace(
                        "- proc proc rw",
                        &format!("shared:2 - proc proc rw,{option}"),
                    );
                    check_mountinfo(s.as_bytes()).unwrap();
                }
                let mut s = MOUNT.to_vec();
                s.extend_from_slice(
                    b"50 23 0:8 / /tmp/a\\040b\\134c rw - tmpfs tmpfs rw,size=1024k\n",
                );
                check_mountinfo(&s).unwrap();
            }
            #[test]
            fn mountinfo_refuses_filtered_rebound_and_unknown_proc_options() {
                let normal = String::from_utf8(MOUNT.to_vec()).unwrap();
                for option in [
                    "hidepid=1",
                    "hidepid=2",
                    "hidepid=invisible",
                    "hidepid=ptraceable",
                    "subset=pid",
                    "pidns=5",
                    "future_filter=1",
                    "gid=-1",
                    "",
                ] {
                    for delimiter in ["rw,nosuid", "proc proc rw"] {
                        let s = normal.replace(delimiter, &format!("{delimiter},{option}"));
                        assert!(check_mountinfo(s.as_bytes()).is_err(), "{s}");
                    }
                }
            }
            #[test]
            fn mountinfo_refuses_bind_root_wrong_fs_missing_and_duplicate_roots() {
                let normal = String::from_utf8(MOUNT.to_vec()).unwrap();
                for s in [
                    normal.replace(" / /proc ", " /123 /proc "),
                    normal.replace("- proc proc", "- tmpfs proc"),
                    normal.replace(" /proc ", " /other "),
                    format!("{normal}{normal}"),
                    format!("{normal}{}", normal.replace("27 23", "28 23")),
                ] {
                    assert!(check_mountinfo(s.as_bytes()).is_err(), "{s}");
                }
            }
            #[test]
            fn mountinfo_refuses_overmounts_before_any_visibility_claim() {
                for path in [
                    "/proc/123",
                    "/proc/self",
                    "/proc/thread-self/stat",
                    "/proc/sys/kernel/random/boot_id",
                    "/proc/a\\040b",
                ] {
                    let mut s = MOUNT.to_vec();
                    s.extend_from_slice(
                        format!("50 27 0:8 / {path} rw - tmpfs tmpfs rw\n").as_bytes(),
                    );
                    assert!(check_mountinfo(&s).is_err(), "{path}");
                }
            }
            #[test]
            fn mountinfo_refuses_noncanonical_paths_before_classification() {
                for path in [
                    "//proc/123",
                    "/proc/../proc/123",
                    "/./proc/123",
                    "/proc//123",
                    "/proc/",
                ] {
                    let mut s = MOUNT.to_vec();
                    s.extend_from_slice(
                        format!("50 27 0:8 / {path} rw - tmpfs tmpfs rw\n").as_bytes(),
                    );
                    assert!(check_mountinfo(&s).is_err(), "{path}");
                }
            }
            #[test]
            fn mountinfo_refuses_malformed_rows_and_escapes() {
                let normal = String::from_utf8(MOUNT.to_vec()).unwrap();
                for s in [
                    normal.replace("0:5", "0:5:6"),
                    normal.replace("0:5", "x:5"),
                    normal.replace("27 23", "id 23"),
                    normal.replace(" - ", " "),
                    normal.replace(" /proc ", " proc "),
                    normal.replace(" /proc ", " /pr\\157c "),
                    normal.replace(" /proc ", " /proc\\ "),
                    normal.replace(" - proc proc rw", " - proc proc"),
                    format!("{normal}broken row\n"),
                ] {
                    assert!(check_mountinfo(s.as_bytes()).is_err(), "{s}");
                }
            }
            #[test]
            fn all_parsers_refuse_empty_nul_and_oversized_sources() {
                for bytes in [vec![], vec![0], vec![b'x'; 1_048_577]] {
                    assert!(parse_stat(&bytes).is_err());
                    assert!(parse_credentials(&bytes).is_err());
                    assert!(check_mountinfo(&bytes).is_err());
                }
            }
        }
    };
}
