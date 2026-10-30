// Constructed busctl get-property replies; no command, file or network access.
use serde_json::{json, Value};

fn reply(signature: &str, value: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": signature, "data": value})).unwrap()
}

fn refused(property: &str, bytes: &[u8]) {
    let error = parse_property(property, bytes).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "invalid systemd property reply");
}

#[test]
fn retains_all_six_scalar_identities_empty_values_and_literal_spellings() {
    let properties = [
        "User",
        "Group",
        "WorkingDirectory",
        "RootDirectory",
        "RootImage",
        "PAMName",
    ];
    // dbus-execute.c encodes the home marker as ~ and missing-ok as !.
    // No caller may silently turn these raw strings into ordinary host paths.
    for value in [
        "",
        "~",
        "!~",
        "!/srv/missing",
        "0",
        "65534",
        "%i",
        "$HOME",
        "../raw/path",
        "/image with spaces",
        "名前\t\n",
        "SENSITIVE-CONTEXT",
    ] {
        let expected = [
            ContextProperty::User(value.into()),
            ContextProperty::Group(value.into()),
            ContextProperty::WorkingDirectory(value.into()),
            ContextProperty::RootDirectory(value.into()),
            ContextProperty::RootImage(value.into()),
            ContextProperty::PamName(value.into()),
        ];
        for (property, expected) in properties.into_iter().zip(expected) {
            assert_eq!(
                parse_property(property, &reply("s", json!(value))).unwrap(),
                expected
            );
        }
    }
}

#[test]
fn keeps_all_three_boolean_projections_and_both_truth_values() {
    for value in [false, true] {
        for (property, expected) in [
            ("DynamicUser", ContextProperty::DynamicUser(value)),
            ("PrivateUsers", ContextProperty::PrivateUsers(value)),
            (
                "SetLoginEnvironment",
                ContextProperty::SetLoginEnvironment(value),
            ),
        ] {
            assert_eq!(
                parse_property(property, &reply("b", json!(value))).unwrap(),
                expected
            );
        }
    }
}

#[test]
fn retains_both_lists_empty_lists_order_duplicates_and_unresolved_text() {
    for values in [
        vec![],
        vec!["z", "a", "z", "relative", "%i", "$PATH", "名前", "/a b"],
    ] {
        let values: Vec<String> = values.into_iter().map(String::from).collect();
        for (property, expected) in [
            (
                "SupplementaryGroups",
                ContextProperty::SupplementaryGroups(values.clone()),
            ),
            (
                "ExecSearchPath",
                ContextProperty::ExecSearchPath(values.clone()),
            ),
        ] {
            assert_eq!(
                parse_property(property, &reply("as", json!(values))).unwrap(),
                expected
            );
        }
    }
}

#[test]
fn rejects_wrong_types_signatures_and_call_return_wrappers() {
    for property in [
        "User",
        "Group",
        "WorkingDirectory",
        "RootDirectory",
        "RootImage",
        "PAMName",
    ] {
        for value in [
            json!(null),
            json!(true),
            json!(0),
            json!(["text"]),
            json!({"value":"text"}),
        ] {
            refused(property, &reply("s", value));
        }
        for signature in ["o", "as", "b", "", "S"] {
            refused(property, &reply(signature, json!("text")));
        }
    }
    for property in ["DynamicUser", "PrivateUsers", "SetLoginEnvironment"] {
        for value in [
            json!(null),
            json!("true"),
            json!(0),
            json!(1),
            json!([true]),
            json!({}),
        ] {
            refused(property, &reply("b", value));
        }
        for signature in ["s", "u", "as", "", "B"] {
            refused(property, &reply(signature, json!(true)));
        }
    }
    for property in ["SupplementaryGroups", "ExecSearchPath"] {
        for value in [
            json!(null),
            json!("text"),
            json!(false),
            json!([1]),
            json!([null]),
            json!([["text"]]),
        ] {
            refused(property, &reply("as", value));
        }
        for signature in ["s", "ao", "b", "", "AS"] {
            refused(property, &reply(signature, json!([])));
        }
    }
}

#[test]
fn rejects_ambiguous_envelopes_trailing_input_and_invalid_encoding() {
    for bytes in [
        b"".as_slice(),
        b"[]",
        br#"["s","value"]"#,
        br#"{"type":"s"}"#,
        br#"{"data":"value"}"#,
        br#"{"type":"s","type":"s","data":"value"}"#,
        br#"{"type":"s","data":"value","data":"value"}"#,
        br#"{"type":"s","data":"value","extra":0}"#,
        br#"{"type":"s","data":"value"}{}"#,
        b"\xff",
        b"\0{}",
        b"\x0b{}",
        br#"{"type":"s","data":"\ud800"}"#,
    ] {
        refused("User", bytes);
    }
    let mut valid = b" \n\r\t".to_vec();
    valid.extend(reply("s", json!("value")));
    valid.extend(b"\n");
    assert_eq!(
        parse_property("User", &valid).unwrap(),
        ContextProperty::User("value".into())
    );
}

#[test]
fn refuses_nul_in_scalars_and_empty_or_nul_list_entries_without_partial_result() {
    for property in [
        "User",
        "Group",
        "WorkingDirectory",
        "RootDirectory",
        "RootImage",
        "PAMName",
    ] {
        refused(property, &reply("s", json!("SENSITIVE-CONTEXT\0suffix")));
    }
    for property in ["SupplementaryGroups", "ExecSearchPath"] {
        for bad in ["", "\0", "a\0b"] {
            refused(property, &reply("as", json!(["valid", bad, "last"])));
        }
    }
}

#[test]
fn bounds_whole_reply_bytes_and_list_count_inclusively() {
    let mut bytes = reply("s", json!("SENSITIVE-CONTEXT"));
    bytes.resize(MAX_BYTES, b' ');
    assert_eq!(
        parse_property("User", &bytes).unwrap(),
        ContextProperty::User("SENSITIVE-CONTEXT".into())
    );
    bytes.push(b' ');
    refused("User", &bytes);
    for property in ["SupplementaryGroups", "ExecSearchPath"] {
        let values = vec!["x"; MAX_ENTRIES];
        let parsed = parse_property(property, &reply("as", json!(values))).unwrap();
        match parsed {
            ContextProperty::SupplementaryGroups(v) | ContextProperty::ExecSearchPath(v) => {
                assert_eq!(v, values)
            }
            _ => panic!("wrong property variant"),
        }
        refused(property, &reply("as", json!(vec!["x"; MAX_ENTRIES + 1])));
    }
}

#[test]
fn unknown_properties_fail_and_debug_or_errors_never_echo_values() {
    for property in [
        "",
        "user",
        "UserEx",
        "Unit.User",
        "RootDirectoryStartOnly",
        "SENSITIVE-CONTEXT",
    ] {
        refused(property, &reply("s", json!("SENSITIVE-CONTEXT")));
    }
    for property in [
        "User",
        "Group",
        "WorkingDirectory",
        "RootDirectory",
        "RootImage",
        "PAMName",
    ] {
        let value = parse_property(property, &reply("s", json!("SENSITIVE-CONTEXT"))).unwrap();
        assert_eq!(format!("{value:?}"), format!("{property}(<redacted>)"));
    }
    for property in ["SupplementaryGroups", "ExecSearchPath"] {
        let value = parse_property(property, &reply("as", json!(["SENSITIVE-CONTEXT"]))).unwrap();
        assert_eq!(format!("{value:?}"), format!("{property}(<redacted>)"));
    }
    for property in ["DynamicUser", "PrivateUsers", "SetLoginEnvironment"] {
        for truth in [true, false] {
            let value = parse_property(property, &reply("b", json!(truth))).unwrap();
            assert_eq!(format!("{value:?}"), format!("{property}(<redacted>)"));
        }
    }
}

fn unit_refused(property: &str, bytes: &[u8]) {
    let error = parse_unit_property(property, bytes).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "invalid systemd property reply");
    assert!(!format!("{error:?}").contains("PRIVATE-UNIT"));
}

// Constructed raw replies follow the systemd v255 dbus-unit.c Unit vtable.
// These are get-property variant bodies, not GetAll or call return envelopes.
#[test]
fn unit_metadata_retains_source_paths_states_and_reload_projections() {
    for (property, bytes, expected) in [
        ("FragmentPath", br#"{"type":"s","data":"/usr/lib/systemd/system/x0xd.service"}"#.as_slice(),
         UnitProperty::FragmentPath("/usr/lib/systemd/system/x0xd.service".into())),
        ("SourcePath", br#"{"type":"s","data":"/etc/init.d/x0xd"}"#,
         UnitProperty::SourcePath("/etc/init.d/x0xd".into())),
        ("DropInPaths", br#"{"type":"as","data":["/run/systemd/system/x0xd.service.d/20-b.conf","/etc/systemd/system/x0xd.service.d/10-a.conf","/run/systemd/system/x0xd.service.d/20-b.conf"]}"#,
         UnitProperty::DropInPaths(vec!["/run/systemd/system/x0xd.service.d/20-b.conf".into(), "/etc/systemd/system/x0xd.service.d/10-a.conf".into(), "/run/systemd/system/x0xd.service.d/20-b.conf".into()])),
        ("LoadState", br#"{"type":"s","data":"loaded"}"#,
         UnitProperty::LoadState("loaded".into())),
        ("UnitFileState", br#"{"type":"s","data":"generated"}"#,
         UnitProperty::UnitFileState("generated".into())),
        ("Transient", br#"{"type":"b","data":false}"#,
         UnitProperty::Transient(false)),
        ("NeedDaemonReload", br#"{"type":"b","data":true}"#,
         UnitProperty::NeedDaemonReload(true)),
    ] {
        assert_eq!(parse_unit_property(property, bytes).unwrap(), expected);
        // The Service entry point must not accept Unit property names.
        refused(property, bytes);
    }
}

#[test]
fn unit_metadata_preserves_empty_or_unresolved_values_without_inference() {
    for value in ["", "../raw path", "%i", "$HOME", "名前\t\n", "PRIVATE-UNIT"] {
        for (property, expected) in [
            ("FragmentPath", UnitProperty::FragmentPath(value.into())),
            ("SourcePath", UnitProperty::SourcePath(value.into())),
        ] {
            assert_eq!(
                parse_unit_property(property, &reply("s", json!(value))).unwrap(),
                expected
            );
        }
    }
    for value in [
        "",
        "loaded",
        "masked",
        "not-found",
        "bad-setting",
        "error",
        "merged",
        "stub",
        "enabled-runtime",
        "transient",
        "generated",
        "future-state",
    ] {
        for (property, expected) in [
            ("LoadState", UnitProperty::LoadState(value.into())),
            ("UnitFileState", UnitProperty::UnitFileState(value.into())),
        ] {
            assert_eq!(
                parse_unit_property(property, &reply("s", json!(value))).unwrap(),
                expected
            );
        }
    }
    for values in [vec![], vec!["../raw", "%i", "$HOME", "名前", "/a b"]] {
        assert_eq!(
            parse_unit_property("DropInPaths", &reply("as", json!(values))).unwrap(),
            UnitProperty::DropInPaths(values.into_iter().map(String::from).collect())
        );
    }
    for value in [true, false] {
        for (property, expected) in [
            ("Transient", UnitProperty::Transient(value)),
            ("NeedDaemonReload", UnitProperty::NeedDaemonReload(value)),
        ] {
            assert_eq!(
                parse_unit_property(property, &reply("b", json!(value))).unwrap(),
                expected
            );
        }
    }
}

#[test]
fn unit_metadata_refuses_wrong_shapes_signatures_and_partial_lists() {
    for (properties, signature, valid) in [
        (
            &["FragmentPath", "SourcePath", "LoadState", "UnitFileState"][..],
            "s",
            json!("PRIVATE-UNIT"),
        ),
        (&["DropInPaths"][..], "as", json!(["PRIVATE-UNIT"])),
        (&["Transient", "NeedDaemonReload"][..], "b", json!(true)),
    ] {
        for property in properties {
            for bad_signature in ["", "o", "u", "a{sv}", "v", "S"] {
                unit_refused(property, &reply(bad_signature, valid.clone()));
            }
            for bad_value in [
                json!(null),
                json!(0),
                json!({"value":valid}),
                json!([valid]),
                json!([null]),
                json!([1]),
            ] {
                unit_refused(property, &reply(signature, bad_value));
            }
            for other_signature in ["s", "as", "b"] {
                if other_signature != signature {
                    unit_refused(property, &reply(other_signature, valid.clone()));
                }
            }
        }
    }
    for property in ["Transient", "NeedDaemonReload"] {
        unit_refused(property, &reply("b", json!("true")));
    }
    unit_refused("DropInPaths", &reply("as", json!("PRIVATE-UNIT")));
    for bad in ["", "\0", "PRIVATE-UNIT\0suffix"] {
        unit_refused("DropInPaths", &reply("as", json!(["valid", bad, "last"])));
    }
    for property in ["FragmentPath", "SourcePath", "LoadState", "UnitFileState"] {
        unit_refused(property, &reply("s", json!("PRIVATE-UNIT\0suffix")));
    }
}

#[test]
fn unit_metadata_refuses_ambiguous_or_malformed_envelopes() {
    for bytes in [
        b"".as_slice(),
        b"[]",
        br#"["s","PRIVATE-UNIT"]"#,
        br#"{"type":"s"}"#,
        br#"{"data":"PRIVATE-UNIT"}"#,
        br#"{"type":"s","type":"s","data":"PRIVATE-UNIT"}"#,
        br#"{"type":"s","data":"PRIVATE-UNIT","data":"PRIVATE-UNIT"}"#,
        br#"{"type":"s","data":"PRIVATE-UNIT","extra":0}"#,
        br#"{"type":"s","data":"PRIVATE-UNIT"}{}"#,
        br#"{"type":"s","data":["PRIVATE-UNIT"]}"#,
        b"\xff",
        b"\0{}",
        b"\x0b{}",
        br#"{"type":"s","data":"\ud800"}"#,
    ] {
        unit_refused("FragmentPath", bytes);
    }
    assert_eq!(
        parse_unit_property("FragmentPath", b" \n\t{\"data\":\"\",\"type\":\"s\"}\r\n").unwrap(),
        UnitProperty::FragmentPath(String::new())
    );
}

#[test]
fn unit_metadata_bounds_entire_reply_and_drop_in_count_inclusively() {
    for (property, signature, value) in [
        ("FragmentPath", "s", json!("PRIVATE-UNIT")),
        ("DropInPaths", "as", json!([])),
        ("Transient", "b", json!(false)),
    ] {
        let mut bytes = reply(signature, value);
        bytes.resize(MAX_BYTES, b' ');
        assert!(parse_unit_property(property, &bytes).is_ok());
        bytes.push(b' ');
        unit_refused(property, &bytes);
    }
    let paths = vec!["/a"; MAX_ENTRIES];
    assert_eq!(
        parse_unit_property("DropInPaths", &reply("as", json!(paths))).unwrap(),
        UnitProperty::DropInPaths(paths.into_iter().map(String::from).collect())
    );
    unit_refused(
        "DropInPaths",
        &reply("as", json!(vec!["/a"; MAX_ENTRIES + 1])),
    );
}

#[test]
fn unit_metadata_refuses_service_or_unknown_properties_and_redacts_all_variants() {
    for property in [
        "",
        "User",
        "WorkingDirectory",
        "Environment",
        "DynamicUser",
        "ExecStart",
        "fragmentpath",
        "Unit.FragmentPath",
        "PRIVATE-UNIT",
    ] {
        unit_refused(property, &reply("s", json!("PRIVATE-UNIT")));
    }
    for (properties, signature, value) in [
        (
            &["FragmentPath", "SourcePath", "LoadState", "UnitFileState"][..],
            "s",
            json!("PRIVATE-UNIT"),
        ),
        (&["DropInPaths"][..], "as", json!(["PRIVATE-UNIT"])),
        (&["Transient", "NeedDaemonReload"][..], "b", json!(true)),
    ] {
        for property in properties {
            let parsed = parse_unit_property(property, &reply(signature, value.clone())).unwrap();
            assert_eq!(format!("{parsed:?}"), format!("{property}(<redacted>)"));
        }
    }
}
