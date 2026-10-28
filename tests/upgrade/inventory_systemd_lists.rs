// Inert supplied-byte controls: no daemon, bus, filesystem or network access.
#[cfg(test)]
mod systemd_lists_tests {
    use super::*;
    use serde_json::{json, Value};

    const LOADED: &[u8] = br#"{"type":"a(ssssssouso)","data":[[["x0xd.service","daemon","loaded","active","running","","/org/freedesktop/systemd1/unit/x0xd_2eservice",0,"","/"]]]}"#;
    const FILES: &[u8] = br#"{"type":"a(ss)","data":[[["/etc/systemd/system/x0xd-443.service","disabled"],["/run/systemd/system/hidden.socket","masked"],["/usr/lib/systemd/system/template@.service","static"]]]}"#;

    fn edited_loaded(index: usize, value: Value) -> Vec<u8> {
        let mut raw: Value = serde_json::from_slice(LOADED).unwrap();
        raw["data"][0][0][index] = value;
        serde_json::to_vec(&raw).unwrap()
    }

    #[test]
    fn raw_method_replies_preserve_fields_and_all_states() {
        let units = loaded(LOADED).unwrap();
        assert_eq!(units.len(), 1);
        assert_eq!(units[0].name, "x0xd.service");
        assert_eq!(units[0].description, "daemon");
        assert_eq!(units[0].load_state, "loaded");
        assert_eq!(units[0].active_state, "active");
        assert_eq!(units[0].sub_state, "running");
        assert!(units[0].following.is_empty());
        assert_eq!(
            units[0].object,
            "/org/freedesktop/systemd1/unit/x0xd_2eservice"
        );
        assert_eq!(units[0].job_id, 0);
        assert!(units[0].job_type.is_empty());
        assert_eq!(units[0].job_object, "/");
        let files = configured(FILES).unwrap();
        assert_eq!(files.len(), 3);
        assert_eq!(
            files[0].path,
            PathBuf::from("/etc/systemd/system/x0xd-443.service")
        );
        assert_eq!(
            files.iter().map(|f| f.state.as_str()).collect::<Vec<_>>(),
            ["disabled", "masked", "static"]
        );
        assert_eq!(
            files[1].path,
            PathBuf::from("/run/systemd/system/hidden.socket")
        );
        assert_eq!(
            files[2].path,
            PathBuf::from("/usr/lib/systemd/system/template@.service")
        );
    }

    #[test]
    fn unloaded_nonservice_alias_and_queued_job_are_retained() {
        let mut raw: Value = serde_json::from_slice(LOADED).unwrap();
        raw["data"][0][0] = json!([
            "alias.socket",
            "",
            "not-found",
            "inactive",
            "dead",
            "primary.socket",
            "/unit/alias",
            4294967295u32,
            "start",
            "/job/4294967295"
        ]);
        let row = loaded(&serde_json::to_vec(&raw).unwrap())
            .unwrap()
            .remove(0);
        assert_eq!(
            (row.name.as_str(), row.following.as_str()),
            ("alias.socket", "primary.socket")
        );
        assert_eq!(
            (
                row.load_state.as_str(),
                row.active_state.as_str(),
                row.sub_state.as_str()
            ),
            ("not-found", "inactive", "dead")
        );
        assert_eq!(
            (row.job_id, row.job_type.as_str(), row.job_object.as_str()),
            (u32::MAX, "start", "/job/4294967295")
        );
    }

    #[test]
    fn empty_supplied_lists_are_valid_data_only() {
        assert!(loaded(br#"{"type":"a(ssssssouso)","data":[[]]}"#)
            .unwrap()
            .is_empty());
        assert!(configured(br#"{"type":"a(ss)","data":[[]]}"#)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn wrong_envelopes_and_trailing_data_refuse() {
        for bytes in [
            br#"["a(ss)",[[]]]"#.as_slice(),
            br#"{"type":"as","data":[[]]}"#.as_slice(),
            br#"{"type":"a(ss)","data":[]}"#,
            br#"{"type":"a(ss)","data":[[],[]]}"#,
            br#"{"type":"a(ss)","data":[["/a.service","enabled"]]}"#,
            br#"{"type":"a(ss)","data":[[]],"extra":0}"#,
            br#"{"type":"a(ss)","type":"a(ss)","data":[[]]}"#,
            br#"{"type":"a(ss)","data":[[]],"data":[[]]}"#,
            br#"{"type":"a(ss)"}"#,
            br#"{"data":[[]]}"#,
            br#"{"type":"a(ss)","data":[[]]} {}"#,
        ] {
            assert!(configured(bytes).is_err(), "{bytes:?}");
        }
        assert!(loaded(FILES).is_err());
        assert!(configured(LOADED).is_err());
    }

    #[test]
    fn every_loaded_field_type_and_tuple_arity_are_checked() {
        for index in [0, 1, 2, 3, 4, 5, 6, 8, 9] {
            assert!(loaded(&edited_loaded(index, json!(7))).is_err());
        }
        for value in [
            json!(-1),
            json!(4294967296u64),
            json!(1.0),
            json!("0"),
            Value::Null,
        ] {
            assert!(loaded(&edited_loaded(7, value)).is_err());
        }
        let mut raw: Value = serde_json::from_slice(LOADED).unwrap();
        raw["data"][0][0].as_array_mut().unwrap().pop();
        assert!(loaded(&serde_json::to_vec(&raw).unwrap()).is_err());
        raw["data"][0][0]
            .as_array_mut()
            .unwrap()
            .extend([json!("/"), json!("extra")]);
        assert!(loaded(&serde_json::to_vec(&raw).unwrap()).is_err());
    }

    #[test]
    fn invalid_names_objects_and_nul_strings_refuse() {
        for name in ["", ".", "..", "a/b.service", "a\n.service"] {
            assert!(loaded(&edited_loaded(0, json!(name))).is_err());
            assert!(loaded(&edited_loaded(
                5,
                json!(if name.is_empty() { "/" } else { name })
            ))
            .is_err());
        }
        for index in [0, 1, 2, 3, 4, 5, 6, 8, 9] {
            assert!(loaded(&edited_loaded(index, json!("secret\0value"))).is_err());
        }
        for index in [6, 9] {
            for object in ["", "relative", "/a/", "/a//b", "/a-b", "/é"] {
                assert!(loaded(&edited_loaded(index, json!(object))).is_err());
            }
        }
        assert!(loaded(&edited_loaded(0, json!("a".repeat(256)))).is_err());
    }

    #[test]
    fn duplicate_loaded_names_and_configured_basenames_refuse() {
        let mut raw: Value = serde_json::from_slice(LOADED).unwrap();
        let mut second = raw["data"][0][0].clone();
        second[6] = json!("/different");
        raw["data"][0].as_array_mut().unwrap().push(second);
        assert!(loaded(&serde_json::to_vec(&raw).unwrap()).is_err());
        for path in ["/etc/a.service", "/run/a.service"] {
            let raw =
                json!({"type":"a(ss)","data":[[["/etc/a.service","enabled"],[path,"masked"]]]});
            assert!(configured(&serde_json::to_vec(&raw).unwrap()).is_err());
        }
    }

    #[test]
    fn configured_ambiguous_paths_and_malformed_rows_refuse_whole_reply() {
        for path in [
            "relative.service",
            "/",
            "/a.service/",
            "/a//b.service",
            "/a/./b.service",
            "/a/../b.service",
            "/secret\0.service",
        ] {
            let raw = json!({"type":"a(ss)","data":[[["/ok.service","enabled"],[path,"masked"]]]});
            assert!(configured(&serde_json::to_vec(&raw).unwrap()).is_err());
        }
        for row in [
            json!(["/a.service"]),
            json!(["/a.service", "enabled", "extra"]),
            json!(["/a.service", 0]),
            json!(["/a.service", "secret\0state"]),
        ] {
            assert!(configured(
                &serde_json::to_vec(&json!({"type":"a(ss)","data":[[row]]})).unwrap()
            )
            .is_err());
        }
    }

    #[test]
    fn byte_and_row_boundaries_are_enforced() {
        let base = br#"{"type":"a(ss)","data":[[]]}"#;
        let mut padded = base.to_vec();
        padded.resize(MAX_BYTES, b' ');
        assert!(configured(&padded).is_ok());
        padded.push(b' ');
        assert!(configured(&padded).is_err());
        let mut rows: Vec<_> = (0..MAX_ROWS)
            .map(|n| json!([format!("/a{n}.service"), "disabled"]))
            .collect();
        assert_eq!(
            configured(&serde_json::to_vec(&json!({"type":"a(ss)","data":[rows]})).unwrap())
                .unwrap()
                .len(),
            MAX_ROWS
        );
        rows.push(json!(["/extra.service", "disabled"]));
        assert!(
            configured(&serde_json::to_vec(&json!({"type":"a(ss)","data":[rows]})).unwrap())
                .is_err()
        );
    }

    #[test]
    fn malformed_raw_input_errors_do_not_echo_values() {
        for bytes in [
            b"secret non-json".as_slice(),
            b"\xffsecret",
            b"{\"secret\":null}",
            b"",
        ] {
            for result in [loaded(bytes).map(|_| ()), configured(bytes).map(|_| ())] {
                let error = result.unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
                assert!(!error.to_string().contains("secret"));
            }
        }
    }

    #[test]
    fn loaded_list_accepts_4096_rows_and_refuses_4097() {
        let mut rows: Vec<_> = (0..4096)
            .map(|n| {
                json!([
                    format!("unit{n}.service"),
                    "description",
                    "loaded",
                    "inactive",
                    "dead",
                    "",
                    format!("/unit/u{n}"),
                    0,
                    "",
                    "/"
                ])
            })
            .collect();
        let raw = serde_json::to_vec(&json!({"type":"a(ssssssouso)","data":[rows]})).unwrap();
        assert!(raw.len() < MAX_BYTES);
        let units = loaded(&raw).unwrap();
        assert_eq!(units.len(), 4096);
        assert_eq!(units.last().unwrap().name, "unit4095.service");
        rows.push(json!([
            "extra.service",
            "",
            "loaded",
            "inactive",
            "dead",
            "",
            "/unit/extra",
            0,
            "",
            "/"
        ]));
        let raw = serde_json::to_vec(&json!({"type":"a(ssssssouso)","data":[rows]})).unwrap();
        assert!(raw.len() < MAX_BYTES);
        assert!(loaded(&raw).is_err());
    }

    #[test]
    fn loaded_debug_redacts_fields_in_leaf_and_nested_formats() {
        let raw = json!({"type":"a(ssssssouso)","data":[[[
            "private.service", "private description", "private-load", "private-active",
            "private-sub", "private-alias.service", "/private/unit", 324567,
            "private-job", "/private/job"
        ]]]});
        let units = loaded(&serde_json::to_vec(&raw).unwrap()).unwrap();
        assert_eq!(units[0].description, "private description");
        assert_eq!(units[0].job_id, 324567);
        for rendered in [
            format!("{:?}", units[0]),
            format!("{:#?}", units[0]),
            format!("{units:?}"),
            format!("{units:#?}"),
        ] {
            assert!(!rendered.contains("private"));
            assert!(!rendered.contains("324567"));
            assert!(rendered.contains("<redacted>"));
        }
    }

    #[test]
    fn configured_debug_redacts_fields_in_leaf_and_nested_formats() {
        let raw = json!({"type":"a(ss)","data":[[["/private/unit.service", "private-state"]]]});
        let files = configured(&serde_json::to_vec(&raw).unwrap()).unwrap();
        assert_eq!(files[0].path, PathBuf::from("/private/unit.service"));
        assert_eq!(files[0].state, "private-state");
        for rendered in [
            format!("{:?}", files[0]),
            format!("{:#?}", files[0]),
            format!("{files:?}"),
            format!("{files:#?}"),
        ] {
            assert!(!rendered.contains("private"));
            assert!(rendered.contains("<redacted>"));
        }
    }
}
