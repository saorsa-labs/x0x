//! Property-based tests for groups.

use proptest::prelude::*;
use x0x::groups::{card::AgentCard, invite::SignedInvite, GroupInfo};
use x0x::identity::AgentId;

fn agent(bytes: [u8; 32]) -> AgentId {
    AgentId(bytes)
}

proptest! {
    #[test]
    fn invite_link_roundtrip(
        group_id_bytes in prop::array::uniform16(any::<u8>()),
        group_name in prop::string::string_regex("[a-zA-Z0-9 -]{1,32}").unwrap(),
        inviter_bytes in prop::array::uniform32(any::<u8>()),
        expiry_secs in 0u64..1_000_000,
    ) {
        let inviter = agent(inviter_bytes);
        let invite = SignedInvite::new(
            hex::encode(group_id_bytes),
            group_name.clone(),
            &inviter,
            expiry_secs,
        );

        let parsed = SignedInvite::from_link(&invite.to_link());
        prop_assert!(parsed.is_ok());
        let parsed = parsed.unwrap();

        prop_assert_eq!(parsed.group_id, invite.group_id);
        prop_assert_eq!(parsed.group_name, group_name);
        prop_assert_eq!(parsed.inviter, invite.inviter);
        prop_assert_eq!(parsed.invite_secret, invite.invite_secret);
        prop_assert_eq!(parsed.expires_at, invite.expires_at);
    }

    #[test]
    fn signable_bytes_deterministic(
        group_id_bytes in prop::array::uniform16(any::<u8>()),
        group_name in prop::string::string_regex("[a-zA-Z0-9 -]{1,32}").unwrap(),
        inviter_bytes in prop::array::uniform32(any::<u8>()),
        expiry_secs in 0u64..1_000_000,
    ) {
        let invite = SignedInvite::new(
            hex::encode(group_id_bytes),
            group_name,
            &agent(inviter_bytes),
            expiry_secs,
        );
        prop_assert_eq!(invite.signable_bytes(), invite.signable_bytes());
    }

    #[test]
    fn general_chat_topic_uses_general_room(
        name in prop::string::string_regex("[a-zA-Z]{1,16}").unwrap(),
        description in prop::string::string_regex("[a-zA-Z0-9 ]{0,32}").unwrap(),
        creator_bytes in prop::array::uniform32(any::<u8>()),
        group_id_bytes in prop::array::uniform16(any::<u8>()),
    ) {
        let info = GroupInfo::new(
            name,
            description,
            agent(creator_bytes),
            hex::encode(group_id_bytes),
        );
        let topic = info.general_chat_topic();
        prop_assert!(topic.starts_with("x0x.group."));
        prop_assert!(topic.ends_with("/general"));
    }

    #[test]
    fn display_name_fallback_is_non_empty(
        name in prop::string::string_regex("[a-zA-Z]{1,16}").unwrap(),
        creator_bytes in prop::array::uniform32(any::<u8>()),
        member_bytes in prop::array::uniform32(any::<u8>()),
        group_id_bytes in prop::array::uniform16(any::<u8>()),
    ) {
        let info = GroupInfo::new(
            name,
            String::new(),
            agent(creator_bytes),
            hex::encode(group_id_bytes),
        );
        let fallback = info.display_name(&hex::encode(member_bytes));
        prop_assert!(!fallback.is_empty());
    }

    #[test]
    fn agent_card_link_roundtrip(
        agent_bytes in prop::array::uniform32(any::<u8>()),
        machine_bytes in prop::array::uniform32(any::<u8>()),
        display_name in prop::string::string_regex("[a-zA-Z0-9_-]{1,16}").unwrap(),
    ) {
        let agent_id = agent(agent_bytes);
        let machine_id = hex::encode(machine_bytes);
        let card = AgentCard::new(display_name.clone(), &agent_id, &machine_id);

        let parsed = AgentCard::from_link(&card.to_link());
        prop_assert!(parsed.is_ok());
        let parsed = parsed.unwrap();

        prop_assert!(parsed.short_display().contains(&parsed.display_name));
        prop_assert_eq!(&parsed.agent_id, &hex::encode(agent_bytes));
        prop_assert_eq!(&parsed.machine_id, &machine_id);
        prop_assert_eq!(parsed.display_name, display_name);
    }
}
