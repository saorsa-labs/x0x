// Constructed busctl get-property replies; no command, file or network access.
use serde_json::{json, Value};

fn reply(signature: &str, value: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": signature, "data": value})).unwrap()
}

fn refused(property: &str, bytes: &[u8]) {
    let error = parse_property(property, bytes).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    assert_eq!(error.to_string(), "invalid execution-context reply");
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
