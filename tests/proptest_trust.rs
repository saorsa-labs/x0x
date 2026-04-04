//! Property-based tests for trust evaluation.

use proptest::prelude::*;
use x0x::contacts::{Contact, ContactStore, IdentityType, TrustLevel};
use x0x::identity::{AgentId, MachineId};
use x0x::trust::{TrustContext, TrustDecision, TrustEvaluator};

fn make_contact(agent: AgentId, trust: TrustLevel, id_type: IdentityType) -> Contact {
    Contact {
        agent_id: agent,
        trust_level: trust,
        label: None,
        added_at: 1000,
        last_seen: None,
        identity_type: id_type,
        machines: vec![],
    }
}

proptest! {
    #[test]
    fn blocked_overrides_all(ab in prop::array::uniform32(any::<u8>()), mb in prop::array::uniform32(any::<u8>())) {
        let a = AgentId(ab);
        let m = MachineId(mb);
        let c = make_contact(a, TrustLevel::Blocked, IdentityType::Pinned);
        let mut s = ContactStore::new(std::path::PathBuf::from("/tmp/x0x-proptest-trust"));
        s.add(c);
        let ctx = TrustContext { agent_id: &a, machine_id: &m };
        prop_assert_eq!(TrustEvaluator::new(&s).evaluate(&ctx), TrustDecision::RejectBlocked);
    }

    #[test]
    fn unknown_agent_returns_unknown(ab in prop::array::uniform32(any::<u8>()), mb in prop::array::uniform32(any::<u8>())) {
        let a = AgentId(ab);
        let m = MachineId(mb);
        let s = ContactStore::new(std::path::PathBuf::from("/tmp/x0x-proptest-trust"));
        let ctx = TrustContext { agent_id: &a, machine_id: &m };
        prop_assert_eq!(TrustEvaluator::new(&s).evaluate(&ctx), TrustDecision::Unknown);
    }

    #[test]
    fn evaluate_is_deterministic(
        ab in prop::array::uniform32(any::<u8>()),
        mb in prop::array::uniform32(any::<u8>()),
        trust in prop_oneof![Just(TrustLevel::Blocked), Just(TrustLevel::Unknown), Just(TrustLevel::Known), Just(TrustLevel::Trusted)],
    ) {
        let a = AgentId(ab);
        let m = MachineId(mb);
        let c = make_contact(a, trust, IdentityType::Anonymous);
        let mut s = ContactStore::new(std::path::PathBuf::from("/tmp/x0x-proptest-trust"));
        s.add(c);
        let ctx = TrustContext { agent_id: &a, machine_id: &m };
        let e = TrustEvaluator::new(&s);
        prop_assert_eq!(e.evaluate(&ctx), e.evaluate(&ctx));
    }

    #[test]
    fn evaluate_has_no_side_effects(ab in prop::array::uniform32(any::<u8>()), mb in prop::array::uniform32(any::<u8>())) {
        let a = AgentId(ab);
        let m = MachineId(mb);
        let c = make_contact(a, TrustLevel::Known, IdentityType::Anonymous);
        let mut s = ContactStore::new(std::path::PathBuf::from("/tmp/x0x-proptest-trust"));
        s.add(c);
        let before = format!("{:?}", s);
        let ctx = TrustContext { agent_id: &a, machine_id: &m };
        let _ = TrustEvaluator::new(&s).evaluate(&ctx);
        prop_assert_eq!(before, format!("{:?}", s));
    }

    #[test]
    fn trust_level_ordering(_seed in 0u64..100) {
        let levels = [TrustLevel::Blocked, TrustLevel::Unknown, TrustLevel::Known, TrustLevel::Trusted];
        let jsons: Vec<String> = levels.iter().map(|l| serde_json::to_string(l).unwrap()).collect();
        for i in 0..jsons.len() {
            for j in (i+1)..jsons.len() {
                prop_assert_ne!(&jsons[i], &jsons[j]);
            }
        }
    }
}
