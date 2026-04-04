//! Property-based tests for direct messaging.

use proptest::prelude::*;
use x0x::direct::{DirectMessage, DIRECT_MESSAGE_STREAM_TYPE, MAX_DIRECT_PAYLOAD_SIZE};
use x0x::identity::{AgentId, MachineId};

proptest! {
    #[test]
    fn max_payload_is_16mib(_seed in 0u64..10) {
        prop_assert_eq!(MAX_DIRECT_PAYLOAD_SIZE, 16 * 1024 * 1024);
    }

    #[test]
    fn stream_type_is_0x10(_seed in 0u64..10) {
        prop_assert_eq!(DIRECT_MESSAGE_STREAM_TYPE, 0x10);
    }

    #[test]
    fn direct_message_constructor_preserves_fields(
        sender_bytes in prop::array::uniform32(any::<u8>()),
        machine_bytes in prop::array::uniform32(any::<u8>()),
        payload in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let sender = AgentId(sender_bytes);
        let machine = MachineId(machine_bytes);
        let msg = DirectMessage::new(sender, machine, payload.clone());

        prop_assert_eq!(msg.sender, sender);
        prop_assert_eq!(msg.machine_id, machine);
        prop_assert_eq!(msg.payload, payload);
    }

    #[test]
    fn payload_str_returns_some_for_utf8(
        sender_bytes in prop::array::uniform32(any::<u8>()),
        machine_bytes in prop::array::uniform32(any::<u8>()),
        text in ".*",
    ) {
        let msg = DirectMessage::new(
            AgentId(sender_bytes),
            MachineId(machine_bytes),
            text.clone().into_bytes(),
        );
        prop_assert_eq!(msg.payload_str(), Some(text.as_str()));
    }

    #[test]
    fn payload_str_returns_none_for_invalid_single_byte(
        sender_bytes in prop::array::uniform32(any::<u8>()),
        machine_bytes in prop::array::uniform32(any::<u8>()),
        invalid_byte in 0x80u8..=0xBFu8,
    ) {
        let msg = DirectMessage::new(
            AgentId(sender_bytes),
            MachineId(machine_bytes),
            vec![invalid_byte],
        );
        prop_assert!(msg.payload_str().is_none());
    }
}
