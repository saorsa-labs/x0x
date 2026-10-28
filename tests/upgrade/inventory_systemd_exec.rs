// Constructed raw replies from systemd v255 dbus-execute.c's property layout
// and busctl.c's get_property/json_transform_variant. No live manager capture.
use serde_json::{json, Value};

const LEGACY: &str = r#"{"type":"a(sasbttttuii)","data":[["/opt/x0x/x0xd",["custom argv0","--name","alice",""],true,11,12,21,22,42,-1,9]]}"#;
const EXTENDED: &str = r#"{"type":"a(sasasttttuii)","data":[["/usr/bin/helper",["helper","$ARG","%i","two words"],["ignore-failure","no-env-expand","future-option"],31,32,41,42,99,1,-9],["x0xd",["x0xd"],[],0,0,0,0,0,0,0]]}"#;

fn parse(text: &str, property: &str) -> io::Result<ExecutionProperty> {
    parse_property(property, text.as_bytes())
}

fn changed(index: usize, value: Value) -> String {
    let mut reply: Value = serde_json::from_str(EXTENDED).unwrap();
    reply["data"][0][index] = value;
    reply.to_string()
}

#[test]
fn legacy_preserves_every_field_and_marks_missing_flag_evidence() {
    let reply = parse(LEGACY, "ExecStart").unwrap();
    assert_eq!(reply.property, "ExecStart");
    assert_eq!(
        reply.commands,
        vec![ExecutionCommand {
            executable: "/opt/x0x/x0xd".into(),
            argv: vec![
                "custom argv0".into(),
                "--name".into(),
                "alice".into(),
                "".into()
            ],
            flags: ExecutionFlags::LegacyIgnoreFailure(true),
            start_realtime_usec: 11,
            start_monotonic_usec: 12,
            exit_realtime_usec: 21,
            exit_monotonic_usec: 22,
            pid: 42,
            code: -1,
            status: 9,
        }]
    );
    assert_eq!(
        parse(&LEGACY.replace("true", "false"), "ExecStop")
            .unwrap()
            .commands[0]
            .flags,
        ExecutionFlags::LegacyIgnoreFailure(false)
    );
}

#[test]
fn extended_retains_helpers_expansions_unknown_flags_and_zero_status() {
    let reply = parse(EXTENDED, "ExecStartPreEx").unwrap();
    assert_eq!(reply.property, "ExecStartPreEx");
    assert_eq!(reply.commands.len(), 2);
    assert_eq!(
        reply.commands[0],
        ExecutionCommand {
            executable: "/usr/bin/helper".into(),
            argv: vec![
                "helper".into(),
                "$ARG".into(),
                "%i".into(),
                "two words".into()
            ],
            flags: ExecutionFlags::Extended(vec![
                "ignore-failure".into(),
                "no-env-expand".into(),
                "future-option".into()
            ]),
            start_realtime_usec: 31,
            start_monotonic_usec: 32,
            exit_realtime_usec: 41,
            exit_monotonic_usec: 42,
            pid: 99,
            code: 1,
            status: -9,
        }
    );
    assert_eq!(reply.commands[1].executable, "x0xd");
    assert_eq!(reply.commands[1].flags, ExecutionFlags::Extended(vec![]));
    assert_eq!(reply.commands[1].pid, 0);
    assert_eq!(reply.commands[1].start_realtime_usec, 0);
    let escaped = changed(1, json!(["héllo", "a\nb", "quote\"slash\\", ""]));
    assert_eq!(
        parse(&escaped, "ExecStartEx").unwrap().commands[0].argv,
        ["héllo", "a\nb", "quote\"slash\\", ""]
    );
}

#[test]
fn retains_repeated_commands_and_all_seven_property_pairs() {
    let mut value: Value = serde_json::from_str(LEGACY).unwrap();
    let command = value["data"][0].clone();
    value["data"].as_array_mut().unwrap().push(command);
    for name in [
        "ExecCondition",
        "ExecStartPre",
        "ExecStart",
        "ExecStartPost",
        "ExecReload",
        "ExecStop",
        "ExecStopPost",
    ] {
        let result = parse(&value.to_string(), name).unwrap();
        assert_eq!(result.commands.len(), 2);
        assert_eq!(result.commands[0], result.commands[1]);
        assert!(parse(EXTENDED, &format!("{name}Ex")).is_ok());
    }
}

#[test]
fn validates_empty_properties_without_erasing_bad_shapes() {
    assert!(parse(r#"{"type":"a(sasbttttuii)","data":[]}"#, "ExecStart")
        .unwrap()
        .commands
        .is_empty());
    assert!(
        parse(r#"{"type":"a(sasasttttuii)","data":[]}"#, "ExecStartEx")
            .unwrap()
            .commands
            .is_empty()
    );
    for name in [
        "",
        "Exec",
        "ExecStartExEx",
        "ExecMain",
        "ExecStart\0",
        "execStart",
        " ExecStart",
        "ExecFoo",
    ] {
        assert!(parse(LEGACY, name).is_err(), "{name:?}");
    }
    assert!(parse(LEGACY, "ExecStartEx").is_err());
    assert!(parse(EXTENDED, "ExecStart").is_err());
    for kind in ["a(sasbttttui)", "", "a(sasasttttuii)"] {
        assert!(parse(&format!(r#"{{"type":"{kind}","data":[]}}"#), "ExecStart").is_err());
    }
}

#[test]
fn refuses_nonobject_duplicate_missing_extra_and_concatenated_envelopes() {
    for raw in [
        r#"["a(sasbttttuii)",[]]"#,
        r#"null"#,
        r#"{}"#,
        r#"{"type":"a(sasbttttuii)"}"#,
        r#"{"data":[]}"#,
        r#"{"type":"a(sasbttttuii)","data":[],"extra":0}"#,
        r#"{"type":"a(sasbttttuii)","type":"a(sasbttttuii)","data":[]}"#,
        r#"{"type":"a(sasbttttuii)","data":[],"data":[]}"#,
        r#"{"type":"a(sasbttttuii)","data":null}"#,
        r#"{"type":"a(sasbttttuii)","data":[[]]}"#,
    ] {
        assert!(parse(raw, "ExecStart").is_err(), "{raw}");
    }
    assert!(parse(&format!("{LEGACY}\n{LEGACY}"), "ExecStart").is_err());
    assert!(parse_property("ExecStart", &[0xff]).is_err());
}

#[test]
fn refuses_wrong_tuple_arity_types_and_method_reply_nesting() {
    for index in 0..10 {
        assert!(parse(&changed(index, Value::Null), "ExecStartEx").is_err());
    }
    let value: Value = serde_json::from_str(EXTENDED).unwrap();
    for extra in [false, true] {
        let mut malformed = value.clone();
        let row = malformed["data"][0].as_array_mut().unwrap();
        if extra {
            row.push(json!(0));
        } else {
            row.pop();
        }
        assert!(parse(&malformed.to_string(), "ExecStartEx").is_err());
    }
    let mut wrapped = value.clone();
    wrapped["data"] = json!([value["data"]]);
    assert!(parse(&wrapped.to_string(), "ExecStartEx").is_err());
    assert!(parse(&changed(2, json!(false)), "ExecStartEx").is_err());
    assert!(parse(&LEGACY.replace("true", "[]"), "ExecStart").is_err());
}

#[test]
fn refuses_nul_and_empty_path_argv_or_flag_without_returning_partial_data() {
    for (index, value) in [
        (0, json!("")),
        (0, json!("a\0b")),
        (1, json!([])),
        (1, json!(["ok", "a\0b"])),
        (2, json!(["ok", ""])),
        (2, json!(["a\0b"])),
    ] {
        let raw = changed(index, value);
        assert!(parse(&raw, "ExecStartEx").is_err(), "index {index}");
        let mut v: Value = serde_json::from_str(&raw).unwrap();
        v["data"].as_array_mut().unwrap().reverse();
        assert!(parse(&v.to_string(), "ExecStartEx").is_err());
    }
    assert!(parse(&LEGACY.replace("alice", "a\\u0000b"), "ExecStart").is_err());
}

#[test]
fn exact_integer_ranges_preserve_status_without_rounding_or_wrapping() {
    for index in 3..7 {
        assert_eq!(
            parse(&changed(index, json!(u64::MAX)), "ExecStartEx")
                .unwrap()
                .commands
                .len(),
            2
        );
        for value in [json!(-1), json!(1.25), json!("1")] {
            assert!(parse(&changed(index, value), "ExecStartEx").is_err());
        }
    }
    assert_eq!(
        parse(&changed(7, json!(u32::MAX)), "ExecStartEx")
            .unwrap()
            .commands[0]
            .pid,
        u32::MAX
    );
    for value in [json!(-1), json!(u64::from(u32::MAX) + 1), json!(1.25)] {
        assert!(parse(&changed(7, value), "ExecStartEx").is_err());
    }
    for index in [8, 9] {
        for value in [i32::MIN, i32::MAX] {
            assert!(parse(&changed(index, json!(value)), "ExecStartEx").is_ok());
        }
        for value in [i64::from(i32::MIN) - 1, i64::from(i32::MAX) + 1] {
            assert!(parse(&changed(index, json!(value)), "ExecStartEx").is_err());
        }
    }
    assert!(parse(
        &changed(3, json!(u64::MAX)).replace("18446744073709551615", "18446744073709551616"),
        "ExecStartEx"
    )
    .is_err());
}

#[test]
fn enforces_input_command_argument_and_flag_capacity_at_boundaries() {
    let mut raw = LEGACY.as_bytes().to_vec();
    raw.resize(MAX_BYTES, b' ');
    assert!(parse_property("ExecStart", &raw).is_ok());
    raw.push(b' ');
    assert!(parse_property("ExecStart", &raw).is_err());
    for (index, cap) in [(1, MAX_ARGUMENTS), (2, MAX_FLAGS)] {
        assert!(parse(&changed(index, json!(vec!["x"; cap])), "ExecStartEx").is_ok());
        assert!(parse(&changed(index, json!(vec!["x"; cap + 1])), "ExecStartEx").is_err());
    }
    let mut value: Value = serde_json::from_str(LEGACY).unwrap();
    let row = value["data"][0].clone();
    value["data"] = json!(vec![row.clone(); MAX_COMMANDS]);
    assert_eq!(
        parse(&value.to_string(), "ExecStart")
            .unwrap()
            .commands
            .len(),
        MAX_COMMANDS
    );
    value["data"].as_array_mut().unwrap().push(row);
    assert!(parse(&value.to_string(), "ExecStart").is_err());
}

fn assert_private_debug(value: &dyn std::fmt::Debug, kind: &str) {
    for rendered in [format!("{value:?}"), format!("{value:#?}")] {
        assert_eq!(rendered, format!("{kind}(<redacted>)"));
    }
}

#[test]
fn debug_execution_property_does_not_print_supplied_arguments() {
    let raw = changed(
        1,
        json!(["helper", "--token=private-token", "private\nargument"]),
    );
    let property = parse(&raw, "ExecStartEx").unwrap();
    assert_private_debug(&property, "ExecutionProperty");
    assert_eq!(property.commands[0].argv[1], "--token=private-token");
    // A containing receipt must not disclose values through nested Debug.
    assert!(!format!("{:#?}", Some(&property)).contains("private"));
}

#[test]
fn debug_execution_command_does_not_print_paths_arguments_or_results() {
    for (raw, name) in [(LEGACY, "ExecStart"), (EXTENDED, "ExecStartEx")] {
        let property = parse(raw, name).unwrap();
        for command in &property.commands {
            assert_private_debug(command, "ExecutionCommand");
        }
    }
}

#[test]
fn debug_execution_flags_does_not_print_unknown_supplied_values() {
    let raw = changed(2, json!(["private-flag", "future\nflag"]));
    let property = parse(&raw, "ExecStartEx").unwrap();
    assert_private_debug(&property.commands[0].flags, "ExecutionFlags");
    assert_eq!(
        property.commands[0].flags,
        ExecutionFlags::Extended(vec!["private-flag".into(), "future\nflag".into()])
    );
    for value in [true, false] {
        assert_private_debug(
            &ExecutionFlags::LegacyIgnoreFailure(value),
            "ExecutionFlags",
        );
    }
}
