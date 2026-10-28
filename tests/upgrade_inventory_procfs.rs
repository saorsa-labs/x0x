// Pure raw-byte controls. No process, filesystem, daemon or network reads.
#[allow(unused_macros)]
macro_rules! inventory_procfs_regression_tests {
    () => {
        mod inventory_procfs_regressions {
            use super::{check_mountinfo, parse_credentials, parse_stat};
            // Representative systemd host, including nsfs and an empty source.
            const MOUNT: &[u8] = concat!(
                "23 1 8:1 / / rw,relatime - ext4 /dev/vda1 rw\n",
                "27 23 0:5 / /proc rw,nosuid,nodev,noexec shared:2 - proc proc rw\n",
                "28 23 0:6 / /sys rw,nosuid,nodev,noexec master:3 propagate_from:4 - sysfs sysfs rw\n",
                "29 23 0:7 / /dev rw,nosuid - devtmpfs udev rw,size=1024k\n",
                "30 29 0:8 / /dev/pts rw,nosuid,noexec - devpts devpts rw,gid=5,mode=620\n",
                "31 23 0:9 / /run rw,nosuid,nodev - tmpfs  rw,mode=755\n",
                "32 28 0:10 / /sys/fs/cgroup rw,nosuid,nodev,noexec unbindable - cgroup2 cgroup rw\n",
                "455 31 0:4 net:[4026532577] /run/netns/x rw shared:248 - nsfs nsfs rw\n",
            ).as_bytes();
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
                for state in b"RSDZTtWXxKPI" {
                    let s = String::from_utf8(stat(b"worker")).unwrap();
                    let s = s.replace(") S ", &format!(") {} ", char::from(*state)));
                    assert_eq!(parse_stat(s.as_bytes()).unwrap().state, *state);
                }
                let mut full = stat(b"worker");
                full.pop();
                full.extend_from_slice(&b" 0".repeat(30)); // Fields 23..52.
                full.push(b'\n');
                assert_eq!(parse_stat(&full).unwrap(), parse_stat(&stat(b"worker")).unwrap());
            }
            #[test]
            fn stat_refuses_malformed_identity_or_truncated_fields() {
                let normal = String::from_utf8(stat(b"worker")).unwrap();
                for s in [
                    normal.replacen("123 ", "0 ", 1),
                    normal.replacen("123 ", "+123 ", 1),
                    normal.replacen("123 ", "0123 ", 1),
                    normal.replacen("123 ", "4294967296 ", 1),
                    normal.replacen("123 ", "4294967295 ", 1),
                    normal.replace(") S ", ") SS "),
                    normal.replace(") S ", ") Q "),
                    normal.replace("987654", "-1"),
                    normal.replace("987654", "0987654"),
                    normal.replace("4194304", "04194304"),
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
                    b"Uid: 01 01 01 01\nGid: 1 1 1 1\n",
                    b"Uid: 1 1 1 1\nGid: 01 01 01 01\n",
                    b"Uid: 4294967296 4294967296 4294967296 4294967296\nGid: 1 1 1 1\n",
                    b"Uid: 4294967295 4294967295 4294967295 4294967295\nGid: 1 1 1 1\n",
                    b"Uid: 1 1 1 1\nGid: 4294967295 4294967295 4294967295 4294967295\n",
                    b"Uid: 1 1 1 1\nGid: 1 1 1 1\nUid: 1 1 1 1\n",
                    b"Uid: 1 1 1 1\nGid: 1 1 1 1\nGid: 1 1 1 1\n",
                ] {
                    assert!(parse_credentials(bad).is_err(), "{bad:?}");
                }
            }
            #[test]
            fn mountinfo_accepts_explicit_unfiltered_root_and_opaque_other_paths() {
                check_mountinfo(MOUNT).unwrap();
                for option in [
                    "hidepid=0",
                    "hidepid=off,gid=4294967294",
                    "nosymfollow,mand",
                ] {
                    let s = String::from_utf8(MOUNT.to_vec()).unwrap().replace(
                        "- proc proc rw",
                        &format!("shared:2 - proc proc rw,{option}"),
                    );
                    check_mountinfo(s.as_bytes()).unwrap();
                }
                let mut s = MOUNT.to_vec();
                s.extend_from_slice(
                    b"50 23 0:8 / /tmp/\xffa\\040b\\134c\\011d\\012e rw - tmpfs tmpfs rw,size=1024k\n",
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
                    "gid=4294967296",
                    "gid=4294967295",
                    "gid=00",
                    "",
                ] {
                    for delimiter in ["rw,nosuid", "proc proc rw"] {
                        let s = normal.replace(delimiter, &format!("{delimiter},{option}"));
                        assert!(check_mountinfo(s.as_bytes()).is_err(), "{s}");
                    }
                }
            }
            #[test]
            fn mountinfo_accepts_each_safe_option_in_both_option_columns() {
                let normal = String::from_utf8(MOUNT.to_vec()).unwrap();
                for option in [
                    "rw", "ro", "nosuid", "nodev", "noexec", "relatime", "strictatime",
                    "noatime", "nodiratime", "sync", "async", "dirsync", "lazytime",
                    "nosymfollow", "mand", "hidepid=0", "hidepid=off", "gid=0",
                    "gid=4294967294",
                ] {
                    for delimiter in ["/proc rw,nosuid,nodev,noexec", "- proc proc rw"] {
                        let prefix = delimiter.rsplit_once(' ').unwrap().0;
                        let s = normal.replace(delimiter, &format!("{prefix} {option}"));
                        check_mountinfo(s.as_bytes()).unwrap_or_else(|e| panic!("{option}: {e}"));
                    }
                }
            }
            #[test]
            fn mountinfo_allows_empty_source_but_no_other_empty_column() {
                check_mountinfo(MOUNT).unwrap();
                let row = "60 23 0:9 / /run/extra rw shared:2 - tmpfs source rw";
                let columns: Vec<_> = row.split(' ').collect();
                for index in 0..columns.len() {
                    let mut changed = columns.clone();
                    changed[index] = "";
                    let mut bytes = MOUNT.to_vec();
                    bytes.extend_from_slice(changed.join(" ").as_bytes());
                    assert_eq!(check_mountinfo(&bytes).is_ok(), index == 9, "column {index}");
                }
            }
            #[test]
            fn stat_requires_every_prefix_through_starttime() {
                let normal = String::from_utf8(stat(b"worker")).unwrap();
                let (prefix, tail) = normal.split_once(") ").unwrap();
                let fields: Vec<_> = tail.split_whitespace().collect();
                assert_eq!(fields.len(), 20);
                parse_stat(normal.as_bytes()).unwrap();
                for count in 0..fields.len() {
                    let cut = format!("{prefix}) {}", fields[..count].join(" "));
                    assert!(parse_stat(cut.as_bytes()).is_err(), "{count} fields");
                }
                let mut bad = normal.replace("4194304", "\u{00ff}").into_bytes();
                assert!(parse_stat(&bad).is_err());
                bad = normal.into_bytes();
                bad[0] = 0xff;
                assert!(parse_stat(&bad).is_err());
            }
            #[test]
            fn mountinfo_refuses_bind_root_wrong_fs_missing_and_duplicate_roots() {
                let normal = String::from_utf8(MOUNT.to_vec()).unwrap();
                let proc = normal.lines().nth(1).unwrap();
                for s in [
                    normal.replace(" / /proc ", " /123 /proc "),
                    normal.replace("- proc proc", "- tmpfs proc"),
                    normal.replace(" /proc ", " /other "),
                    format!("{normal}{normal}"),
                    format!("{normal}{}", proc.replace("27 23", "127 23")),
                ] {
                    assert!(check_mountinfo(s.as_bytes()).is_err(), "{s}");
                }
            }
            #[test]
            fn mountinfo_refuses_overmounts_and_noncanonical_paths() {
                for path in [
                    "/proc/123",
                    "/proc/self",
                    "/proc/thread-self/stat",
                    "/proc/sys/kernel/random/boot_id",
                    "/proc/a\\040b",
                    "/proc/sys/fs/binfmt_misc",
                    "/proc/sys/fs/binfmt_misc/child",
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
                    normal.replace("27 23", "027 23"),
                    normal.replace("27 23", "27 023"),
                    normal.replace("0:5", "00:5"),
                    normal.replace(" - proc", " shared:0 - proc"),
                    normal.replace(" - proc", " master:x - proc"),
                    normal.replace(" - proc", " propagate_from:01 - proc"),
                    normal.replace(" - proc", " unknown:1 - proc"),
                    normal.replace(" / /proc ", " /proc ").replace(" shared:2", ""),
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
            fn mountinfo_accepts_host_root_after_proc() {
                let s = String::from_utf8(MOUNT.to_vec()).unwrap();
                let (root, rest) = s.split_once('\n').unwrap();
                check_mountinfo(format!("{rest}{root}\n").as_bytes()).unwrap();
            }
            #[test]
            fn mountinfo_allows_only_exact_binfmt_mounts() {
                for fs in ["autofs", "binfmt_misc"] {
                    let mut s = MOUNT.to_vec();
                    s.extend_from_slice(
                        format!("50 27 0:8 / /proc/sys/fs/binfmt_misc rw - {fs} systemd-1 rw\n")
                            .as_bytes(),
                    );
                    check_mountinfo(&s).unwrap();
                    // An activated automount can retain both rows at the same path.
                    let mut stacked = s.clone();
                    stacked.extend_from_slice(b"51 50 0:11 / /proc/sys/fs/binfmt_misc rw - binfmt_misc binfmt_misc rw\n");
                    check_mountinfo(&stacked).unwrap();
                    for path in ["/proc/sys", "/proc/sys/fs/binfmt_misc/child", "/proc/123"] {
                        let bad = String::from_utf8(s.clone())
                            .unwrap()
                            .replace("/proc/sys/fs/binfmt_misc ", &format!("{path} "));
                        assert!(check_mountinfo(bad.as_bytes()).is_err(), "{bad}");
                    }
                }
            }
            #[test]
            fn mountinfo_refuses_hidden_proc_or_missing_root() {
                let s = String::from_utf8(MOUNT.to_vec()).unwrap();
                for bad in [
                    s.replace("27 23", "27 99"),
                    s.lines().skip(1).collect::<Vec<_>>().join("\n"),
                    format!("{s}51 23 8:2 / / rw - ext4 /dev/vdb1 rw\n"),
                    format!("51 23 8:2 / / rw - ext4 /dev/vdb1 rw\n{s}"),
                ] {
                    assert!(check_mountinfo(bad.as_bytes()).is_err(), "{bad}");
                }
            }
            #[test]
            fn all_parsers_enforce_bounds_with_specific_refusals() {
                let empty = parse_stat(b"").unwrap_err();
                let s = String::from_utf8(stat(b"worker"))
                    .unwrap()
                    .replacen("123 ", "0123 ", 1);
                let numeric = parse_stat(s.as_bytes()).unwrap_err();
                assert_eq!(empty.kind(), std::io::ErrorKind::InvalidData);
                assert_eq!(numeric.kind(), std::io::ErrorKind::InvalidData);
                assert_ne!(empty.to_string(), numeric.to_string());
                for bytes in [vec![], vec![0], vec![b'x'; 1_048_577]] {
                    assert!(parse_stat(&bytes).is_err());
                    assert!(parse_credentials(&bytes).is_err());
                    assert!(check_mountinfo(&bytes).is_err());
                }
                let pad = |mut bytes: Vec<u8>| { bytes.resize(1_048_576, b'\n'); bytes };
                parse_stat(&pad(stat(b"worker"))).unwrap();
                parse_credentials(&pad(STATUS.to_vec())).unwrap();
                check_mountinfo(&pad(MOUNT.to_vec())).unwrap();
            }
        }
    };
}
