// Expanded inside upgrade::fleet_policy by the lead. The standalone integration
// target has no tests. These are private policy controls, not host inventory,
// service-manager verification, or proof that a real trigger enforces the policy.
#[allow(unused_macros)]
macro_rules! fleet_policy_regression_tests {
    () => {
        #[cfg(test)]
        mod fleet_policy_regressions {
            use super::*;

            fn verified(unit: &str, user_manager: bool) -> SystemdVerifiedUnit {
                SystemdVerifiedUnit {
                    unit: unit.into(), user_manager, restart: "always".into(), template_version: None,
                }
            }

            fn fixture() -> tempfile::TempDir {
                let root = std::env::var_os("X0X_UPGRADE_FLEET_EVIDENCE_DIR")
                    .map(PathBuf::from)
                    .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                        .join(".planning/upgrade-fleet-fixtures"));
                std::fs::create_dir_all(&root).unwrap();
                tempfile::Builder::new().prefix("fleet-").tempdir_in(root).unwrap()
            }

            #[test]
            fn fleet_tracked_pairs_and_partial_signals_keep_the_production_floor() {
                let authority = parse_authority(AUTHORITY).unwrap();
                for entry in &authority {
                    let service = verified(&entry.unit, false);
                    assert_eq!(classify(&entry.binary, Some(&service), &authority), Classification::Fleet);
                    let user = verified(&entry.unit, true);
                    for (install, service) in [
                        (entry.binary.as_path(), None),
                        (entry.binary.as_path(), Some(&user)),
                        (Path::new("/owned-ordinary-fixture/x0xd"), Some(&service)),
                    ] {
                        assert_eq!(classify(install, service, &authority), Classification::AmbiguousFleet);
                    }
                }
                // Pure policy controls explicitly select the production rule.
                // They do not prove which key branch effective_window compiled.
                for classification in [Classification::Fleet, Classification::AmbiguousFleet] {
                    for (configured, expected) in [(0,60),(59,60),(60,60),(61,61),(u64::MAX,u64::MAX)] {
                        let actual = policy(configured, classification, false);
                        assert_eq!(actual.window_minutes, expected);
                        assert_eq!(actual.minimum_window_minutes, 60);
                    }
                }
            }

            #[test]
            fn fleet_ordinary_windows_and_explicit_rehearsal_policy_are_distinct() {
                let authority = parse_authority(AUTHORITY).unwrap();
                let service = verified("owned-untracked.service", false);
                let ordinary = classify(Path::new("/owned-ordinary-fixture/x0xd"), Some(&service), &authority);
                assert_eq!(ordinary, Classification::Ordinary);
                for configured in [0,1,59,60,u64::MAX] {
                    let ordinary = policy(configured, ordinary, false);
                    assert_eq!(ordinary.window_minutes, configured);
                    assert_eq!(ordinary.minimum_window_minutes, 0);
                    assert_eq!(policy(configured, Classification::Fleet, true).window_minutes, configured);
                }
            }

            // This invokes the real compile-time selector. The synthetic verified
            // plan is a policy input only; no manager, daemon or socket is started.
            fn assert_compiled_policy(expected_minimum: u64) {
                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                let install = root.join("x0xd");
                std::fs::write(&install, b"owned policy fixture").unwrap();
                let authority = parse_authority(AUTHORITY).unwrap();
                let plan = RestartPlan {
                    mode: crate::upgrade::restart::RestartMode::SupervisedExit,
                    supervised_exit_code: Some(0), supervision_signal: Some("systemd".into()),
                    executable: install.clone(), argv: vec![install.to_str().unwrap().into()],
                    cwd: root.clone(), data_root: root,
                    api_addr: "127.0.0.1:1".parse().unwrap(), launchd_verified: None,
                    systemd_verified: Some(verified(&authority[0].unit, false)),
                };
                let actual = effective_window(0, &install, &plan).unwrap();
                assert_eq!(actual.classification, Classification::AmbiguousFleet);
                assert_eq!(actual.window_minutes, expected_minimum);
                assert_eq!(actual.minimum_window_minutes, expected_minimum);
                let mut mismatched = plan.clone();
                mismatched.executable = dir.path().join("another-binary");
                std::fs::write(&mismatched.executable, b"different owned file").unwrap();
                assert!(effective_window(0, &install, &mismatched).is_err());
                assert_eq!(std::fs::read(install).unwrap(), b"owned policy fixture");
            }

            // An --all-features build does NOT compile or execute this test.
            #[cfg(not(feature = "upgrade-test-signing"))]
            #[test]
            fn fleet_effective_window_uses_the_production_trust_branch() {
                assert_compiled_policy(60);
            }

            #[cfg(all(feature = "upgrade-test-signing", debug_assertions))]
            #[test]
            fn fleet_effective_window_waives_only_in_the_compiled_debug_test_key_branch() {
                assert_compiled_policy(0);
            }

            #[cfg(unix)]
            #[test]
            fn fleet_tracked_symlinks_remain_positive_and_uncertain_resolution_refuses() {
                use std::os::unix::fs::symlink;
                let dir = fixture();
                let root = dir.path().canonicalize().unwrap();
                let target = root.join("real-x0xd");
                std::fs::write(&target, b"owned executable bytes").unwrap();
                let tracked = root.join("tracked-x0xd");
                symlink(&target, &tracked).unwrap();
                let entry = |binary| FleetAuthority {
                    binary, resolved_binary: None, unit: "owned-fleet.service".into(),
                };
                let resolved = resolve_authority(vec![entry(tracked.clone())]).unwrap();
                assert_eq!(classify(&target, None, &resolved), Classification::AmbiguousFleet);
                assert_eq!(classify(&target, Some(&verified("owned-fleet.service", false)), &resolved),
                    Classification::Fleet);
                let absent = resolve_authority(vec![entry(root.join("absent"))]).unwrap();
                assert!(absent[0].resolved_binary.is_none());
                assert_eq!(classify(&target, None, &absent), Classification::Ordinary);
                let uncertain = root.join("symlink-loop");
                symlink(&uncertain, &uncertain).unwrap();
                // ELOOP is deterministic even as root; chmod000 is not.
                assert!(resolve_authority(vec![entry(uncertain)]).is_err());
                assert_eq!(std::fs::read(target).unwrap(), b"owned executable bytes");
                assert_eq!(std::fs::read_link(tracked).unwrap(), root.join("real-x0xd"));
            }

            #[test]
            fn fleet_old_window_refuses_without_offering_a_replacement_receipt() {
                let enforced = policy(60, Classification::Fleet, false);
                for recorded in [0,1,59] {
                    assert_eq!(enforced.check_receipt_window(recorded).unwrap_err().kind(),
                        io::ErrorKind::PermissionDenied);
                }
                for recorded in [60,61,u64::MAX] {
                    enforced.check_receipt_window(recorded).unwrap();
                }
                // This guard receives only the frozen window, not chosen delay
                // or writable receipt state. Storage preservation is a separate
                // integration obligation; a legitimate chosen delay may be0.
                policy(0, Classification::Ordinary, false).check_receipt_window(0).unwrap();
                policy(0, Classification::Fleet, true).check_receipt_window(0).unwrap();
            }

            #[test]
            fn fleet_embedded_authority_rejects_unknown_or_ambiguous_inputs() {
                let original: serde_json::Value = serde_json::from_str(AUTHORITY).unwrap();
                let mut invalid = vec![serde_json::json!({"schema_version":1,"instances":[]})];
                for field in ["schema", "nested", "duplicate", "binary", "unit", "source", "selector"] {
                    let mut value = original.clone();
                    match field {
                        "schema" => value["schema_version"] = serde_json::json!(99),
                        "nested" => value["instances"][0]["binary"]["extra"] = serde_json::json!(true),
                        "duplicate" => {
                            let duplicate = value["instances"][0].clone();
                            value["instances"].as_array_mut().unwrap().push(duplicate);
                        }
                        "binary" => value["instances"][0]["binary"]["destination"] = serde_json::json!("/opt/../other"),
                        "unit" => value["instances"][0]["unit"]["destination"] = serde_json::json!("/etc/systemd/user/owned.service"),
                        "source" => value["instances"][0]["unit"]["source"] = serde_json::json!("../outside.service"),
                        _ => value["instances"][0]["installation"]["selector_args"] = serde_json::json!(["--instance","wrong"]),
                    }
                    invalid.push(value);
                }
                for value in invalid {
                    assert!(parse_authority(&serde_json::to_string(&value).unwrap()).is_err());
                }
                parse_authority(AUTHORITY).unwrap();
            }
        }
    };
}
