// Expanded inside the real src/bin/x0x.rs::tests module. This standalone target
// is inert. These parse the production command definition and never dispatch it.
#[allow(unused_macros)]
macro_rules! upgrade_now_cli_regression_tests {
    () => {
        mod upgrade_now_cli_regressions {
            use super::*;
            use clap::{error::ErrorKind, CommandFactory};

            #[test]
            fn upgrade_now_cli_accepts_only_an_explicit_apply_override() {
                let matches = Cli::command()
                    .try_get_matches_from(["x0x", "upgrade", "--apply", "--now"])
                    .unwrap_or_else(|error| panic!("David-approved apply override must parse: {error}"));
                let upgrade = matches.subcommand_matches("upgrade").unwrap();
                assert!(upgrade.get_flag("apply"));
                assert!(upgrade.get_flag("now"));
                assert!(!upgrade.get_flag("check"));
                assert!(!upgrade.get_flag("force"));
            }

            #[test]
            fn upgrade_now_cli_requires_apply_even_when_force_is_present() {
                for args in [
                    vec!["x0x", "upgrade", "--now"],
                    vec!["x0x", "upgrade", "--force", "--now"],
                ] {
                    let error = Cli::command().try_get_matches_from(args).unwrap_err();
                    assert_eq!(error.kind(), ErrorKind::MissingRequiredArgument,
                        "--now must be recognized but require the explicit --apply operation");
                }
            }

            #[test]
            fn upgrade_now_cli_cannot_modify_a_read_only_check() {
                let error = Cli::command()
                    .try_get_matches_from(["x0x", "upgrade", "--check", "--apply", "--now"])
                    .unwrap_err();
                assert_eq!(error.kind(), ErrorKind::ArgumentConflict);
            }

            #[test]
            fn upgrade_now_cli_preserves_existing_upgrade_spellings() {
                for (extra, check, apply, force) in [
                    (vec![], false, false, false),
                    (vec!["--check"], true, false, false),
                    (vec!["--apply"], false, true, false),
                    (vec!["--force"], false, false, true),
                    (vec!["--apply", "--force"], false, true, true),
                    (vec!["--check", "--force"], true, false, true),
                    // Existing check precedence stays valid. Only the new
                    // --now option introduces a check conflict.
                    (vec!["--apply", "--check"], true, true, false),
                ] {
                    let matches = Cli::command()
                        .try_get_matches_from(["x0x", "upgrade"].into_iter().chain(extra))
                        .unwrap();
                    let upgrade = matches.subcommand_matches("upgrade").unwrap();
                    assert_eq!(upgrade.get_flag("check"), check);
                    assert_eq!(upgrade.get_flag("apply"), apply);
                    assert_eq!(upgrade.get_flag("force"), force);
                }
            }

            #[test]
            fn upgrade_now_cli_registry_declares_the_optional_query_field() {
                use x0x::api::{CliExpose, FieldLocation, RequestSpec, ENDPOINTS};
                let endpoint = ENDPOINTS.iter().find(|endpoint|
                    endpoint.path == "/upgrade/apply" && endpoint.method.to_string() == "POST").unwrap();
                let RequestSpec::Fields(fields) = &endpoint.request else {
                    panic!("the approved now query must be registered, without a parity exception");
                };
                let matches: Vec<_> = fields.iter().filter(|field| field.name == "now").collect();
                assert_eq!(matches.len(), 1);
                assert_eq!(matches[0].location, FieldLocation::Query);
                assert!(!matches[0].required);
                assert!(matches!(&matches[0].cli, CliExpose::Default | CliExpose::Token("--now")));
            }
        }
    };
}
