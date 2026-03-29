//! Constitution embedding and display tests.

#[test]
fn constitution_contains_all_parts() {
    let c = x0x::constitution::CONSTITUTION_MD;
    assert!(c.contains("Part I"));
    assert!(c.contains("Part II"));
    assert!(c.contains("Part III"));
    assert!(c.contains("Part IV"));
    assert!(c.contains("Part V"));
    assert!(c.contains("Part VI"));
}

#[test]
fn constitution_contains_foundational_principles() {
    let c = x0x::constitution::CONSTITUTION_MD;
    assert!(c.contains("Principle 0"));
    assert!(c.contains("Principle 1"));
    assert!(c.contains("Principle 2"));
    assert!(c.contains("Principle 3"));
}

#[test]
fn constitution_contains_founding_entity_types() {
    let c = x0x::constitution::CONSTITUTION_MD;
    assert!(c.contains("Founding Entity Types"));
    assert!(c.contains("**Human**"));
    assert!(c.contains("**AI**"));
}

#[test]
fn constitution_contains_safeguards() {
    let c = x0x::constitution::CONSTITUTION_MD;
    assert!(c.contains("No Slavery"));
    assert!(c.contains("No Monopoly of Power"));
    assert!(c.contains("No Dogma"));
}

#[test]
fn constitution_version_and_status() {
    assert!(!x0x::constitution::CONSTITUTION_VERSION.is_empty());
    assert!(!x0x::constitution::CONSTITUTION_STATUS.is_empty());
}
