// Constructed from systemd v255 dbus-execute.c:71-98,947-950 and busctl's
// get-property JSON envelope. These are not captured live-manager fixtures.
use serde_json::json;

fn reply(signature: &str, data: serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": signature, "data": data})).unwrap()
}

#[test]
fn assignments_keep_order_duplicates_empty_values_and_literal_text() {
    let raw = br#"{"type":"as","data":["X0X_DATA_DIR=/first","X0X_DATA_DIR=/last","EMPTY=","LITERAL=$HOME/%h/*.env","UNICODE=\u03bb","MULTILINE=a\nb","EQUAL=a=b"]}"#;
    assert_eq!(
        parse_property("Environment", raw).unwrap(),
        EnvironmentProperty::Environment(vec![
            "X0X_DATA_DIR=/first".into(),
            "X0X_DATA_DIR=/last".into(),
            "EMPTY=".into(),
            "LITERAL=$HOME/%h/*.env".into(),
            "UNICODE=λ".into(),
            "MULTILINE=a\nb".into(),
            "EQUAL=a=b".into(),
        ])
    );
}

#[test]
fn files_keep_optional_flags_duplicates_and_unresolved_paths() {
    let raw = br#"{"type":"a(sb)","data":[["/etc/x0x/one.env",false],["/etc/x0x/*.env",true],["/etc/x0x/one.env",true],["%h/local.env",false],["relative",true]]}"#;
    assert_eq!(
        parse_property("EnvironmentFiles", raw).unwrap(),
        EnvironmentProperty::Files(vec![
            EnvironmentFile {
                path: "/etc/x0x/one.env".into(),
                ignore_missing: false
            },
            EnvironmentFile {
                path: "/etc/x0x/*.env".into(),
                ignore_missing: true
            },
            EnvironmentFile {
                path: "/etc/x0x/one.env".into(),
                ignore_missing: true
            },
            EnvironmentFile {
                path: "%h/local.env".into(),
                ignore_missing: false
            },
            EnvironmentFile {
                path: "relative".into(),
                ignore_missing: true
            },
        ])
    );
}

#[test]
fn pass_and_unset_remain_distinct_typed_evidence() {
    assert_eq!(
        parse_property(
            "PassEnvironment",
            br#"{"type":"as","data":["HOME","X0X_DATA_DIR","HOME"]}"#
        )
        .unwrap(),
        EnvironmentProperty::Pass(vec!["HOME".into(), "X0X_DATA_DIR".into(), "HOME".into()])
    );
    assert_eq!(
        parse_property(
            "UnsetEnvironment",
            br#"{"type":"as","data":["HOME","X0X_DATA_DIR=/old","EMPTY=","HOME"]}"#
        )
        .unwrap(),
        EnvironmentProperty::Unset(vec![
            "HOME".into(),
            "X0X_DATA_DIR=/old".into(),
            "EMPTY=".into(),
            "HOME".into()
        ])
    );
}

#[test]
fn empty_arrays_and_json_whitespace_are_accepted_for_all_four_properties() {
    for (property, signature, expected) in [
        (
            "Environment",
            "as",
            EnvironmentProperty::Environment(vec![]),
        ),
        (
            "EnvironmentFiles",
            "a(sb)",
            EnvironmentProperty::Files(vec![]),
        ),
        ("PassEnvironment", "as", EnvironmentProperty::Pass(vec![])),
        ("UnsetEnvironment", "as", EnvironmentProperty::Unset(vec![])),
    ] {
        let mut raw = b" \r\n\t".to_vec();
        raw.extend(reply(signature, json!([])));
        raw.extend(b"\n\t");
        assert_eq!(parse_property(property, &raw).unwrap(), expected);
    }
}

#[test]
fn unsupported_names_and_signatures_refuse_even_empty_arrays() {
    for name in [
        "",
        "environment",
        "EnvironmentFile",
        "EnvironmentEx",
        "ManagerEnvironment",
        "ExecStart",
    ] {
        assert!(parse_property(name, &reply("as", json!([]))).is_err());
    }
    for name in [
        "Environment",
        "PassEnvironment",
        "UnsetEnvironment",
        "EnvironmentFiles",
    ] {
        for signature in ["", "s", "a{ss}", "aas", "a(sb)as", " as"] {
            assert!(parse_property(name, &reply(signature, json!([]))).is_err());
        }
        let wrong = if name == "EnvironmentFiles" {
            "as"
        } else {
            "a(sb)"
        };
        assert!(parse_property(name, &reply(wrong, json!([]))).is_err());
    }
}

#[test]
fn malformed_envelopes_cannot_be_valid_empty_evidence() {
    for raw in [
        "",
        "null",
        "[]",
        r#"["as",[]]"#,
        r#"{"type":"as"}"#,
        r#"{"data":[]}"#,
        r#"{"type":"as","data":null}"#,
        r#"{"type":"as","data":{},"extra":false}"#,
        r#"{"type":"as","data":[],"extra":false}"#,
        r#"{"type":"as","type":"as","data":[]}"#,
        r#"{"type":"as","data":[],"data":[]}"#,
        r#"{"type":"as","data":[]} {}"#,
        r#"{"type":1,"data":[]}"#,
    ] {
        assert!(
            parse_property("Environment", raw.as_bytes()).is_err(),
            "{raw}"
        );
    }
    assert!(parse_property("Environment", b"\x0c{\"type\":\"as\",\"data\":[]}").is_err());
    assert!(parse_property("Environment", b"{\"type\":\"as\",\"data\":[\"\xff\"]}").is_err());
}

#[test]
fn wrong_row_types_and_tuple_arity_refuse_whole_reply() {
    for row in [
        json!(null),
        json!(true),
        json!(1),
        json!(["A=B"]),
        json!({"A":"B"}),
    ] {
        for property in ["Environment", "PassEnvironment", "UnsetEnvironment"] {
            assert!(parse_property(property, &reply("as", json!(["VALID=x", row]))).is_err());
        }
    }
    for row in [
        json!([]),
        json!(["/file"]),
        json!(["/file", false, 0]),
        json!(["/file", "true"]),
        json!(["/file", 0]),
        json!([null, false]),
        json!([1, false]),
        json!({"path":"/file","ignore_missing":false}),
    ] {
        assert!(parse_property(
            "EnvironmentFiles",
            &reply("a(sb)", json!([["/valid", false], row]))
        )
        .is_err());
    }
}

#[test]
fn invalid_entries_refuse_in_every_property_without_echoing_values() {
    for bad in ["", "SECRET_DO_NOT_ECHO\0value"] {
        for property in [
            "Environment",
            "PassEnvironment",
            "UnsetEnvironment",
            "EnvironmentFiles",
        ] {
            let raw = if property == "EnvironmentFiles" {
                reply("a(sb)", json!([["/valid", false], [bad, true]]))
            } else {
                reply("as", json!(["VALID=first", bad]))
            };
            let error = parse_property(property, &raw).unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            assert!(!error.to_string().contains("SECRET_DO_NOT_ECHO"));
        }
    }
    let raw = br#"{"type":"as","data":[{"SECRET_DO_NOT_ECHO":false}]}"#;
    assert!(!parse_property("Environment", raw)
        .unwrap_err()
        .to_string()
        .contains("SECRET_DO_NOT_ECHO"));
}

#[test]
fn exact_input_and_entry_limits_are_enforced() {
    for (property, signature, row) in [
        ("Environment", "as", json!("A=B")),
        ("PassEnvironment", "as", json!("HOME")),
        ("UnsetEnvironment", "as", json!("HOME")),
        ("EnvironmentFiles", "a(sb)", json!(["/file", true])),
    ] {
        let at = reply(signature, json!(vec![row.clone(); MAX_ENTRIES]));
        assert!(parse_property(property, &at).is_ok());
        let over = reply(signature, json!(vec![row; MAX_ENTRIES + 1]));
        assert!(parse_property(property, &over).is_err());
        let mut padded = reply(signature, json!([]));
        padded.resize(MAX_BYTES, b' ');
        assert!(parse_property(property, &padded).is_ok());
        padded.push(b' ');
        assert!(parse_property(property, &padded).is_err());
    }
}

#[test]
fn debug_environment_properties_do_not_disclose_assignments_names_or_paths() {
    for (name, signature, data) in [
        (
            "Environment",
            "as",
            json!(["SECRET=private-token", "MULTILINE=private\nvalue"]),
        ),
        ("PassEnvironment", "as", json!(["PRIVATE_VARIABLE"])),
        ("UnsetEnvironment", "as", json!(["SECRET=private-token"])),
        (
            "EnvironmentFiles",
            "a(sb)",
            json!([["/private/account/secret.env", true]]),
        ),
    ] {
        let property = parse_property(name, &reply(signature, data)).unwrap();
        assert_eq!(format!("{property:?}"), "EnvironmentProperty(<redacted>)");
        assert_eq!(format!("{property:#?}"), "EnvironmentProperty(<redacted>)");
        assert!(!format!("{:#?}", Some(&property)).contains("private"));
    }
}

#[test]
fn debug_environment_file_does_not_disclose_its_supplied_path() {
    let property = parse_property(
        "EnvironmentFiles",
        &reply("a(sb)", json!([["/private/account/secret.env", true]])),
    )
    .unwrap();
    let EnvironmentProperty::Files(files) = property else {
        panic!("expected files")
    };
    assert_eq!(format!("{:?}", files[0]), "EnvironmentFile(<redacted>)");
    assert_eq!(format!("{:#?}", files[0]), "EnvironmentFile(<redacted>)");
    assert_eq!(files[0].path, "/private/account/secret.env");
    assert!(files[0].ignore_missing);
}
