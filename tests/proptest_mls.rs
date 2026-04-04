//! Property-based tests for MLS primitives.

use proptest::prelude::*;
use x0x::identity::AgentId;
use x0x::mls::{CommitOperation, MlsCipher, MlsGroup, MlsKeySchedule};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

proptest! {
    #[test]
    fn cipher_encrypt_decrypt_roundtrip(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform12(any::<u8>()),
        aad in prop::collection::vec(any::<u8>(), 0..64),
        plaintext in prop::collection::vec(any::<u8>(), 0..512),
        counter in any::<u64>(),
    ) {
        let cipher = MlsCipher::new(key.to_vec(), nonce.to_vec());
        let ciphertext = cipher.encrypt(&plaintext, &aad, counter).unwrap();
        let decrypted = cipher.decrypt(&ciphertext, &aad, counter).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn different_counters_produce_different_ciphertexts(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform12(any::<u8>()),
        aad in prop::collection::vec(any::<u8>(), 0..64),
        plaintext in prop::collection::vec(any::<u8>(), 1..128),
        counter_a in any::<u64>(),
        counter_b in any::<u64>(),
    ) {
        prop_assume!(counter_a != counter_b);

        let cipher = MlsCipher::new(key.to_vec(), nonce.to_vec());
        let left = cipher.encrypt(&plaintext, &aad, counter_a).unwrap();
        let right = cipher.encrypt(&plaintext, &aad, counter_b).unwrap();
        prop_assert_ne!(left, right);
    }

    #[test]
    fn group_encrypt_decrypt_roundtrip(
        group_id in prop::collection::vec(any::<u8>(), 1..32),
        initiator_bytes in prop::array::uniform32(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let runtime = rt();
        let initiator = AgentId(initiator_bytes);
        let group = runtime.block_on(MlsGroup::new(group_id, initiator)).unwrap();

        let ciphertext = group.encrypt_message(&plaintext).unwrap();
        let decrypted = group.decrypt_message(&ciphertext).unwrap();
        prop_assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn group_add_member_advances_epoch(
        group_id in prop::collection::vec(any::<u8>(), 1..32),
        initiator_bytes in prop::array::uniform32(any::<u8>()),
        member_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        prop_assume!(initiator_bytes != member_bytes);

        let runtime = rt();
        let initiator = AgentId(initiator_bytes);
        let member = AgentId(member_bytes);
        let mut group = runtime.block_on(MlsGroup::new(group_id, initiator)).unwrap();
        let epoch_before = group.current_epoch();

        let commit = runtime.block_on(group.add_member(member)).unwrap();

        prop_assert_eq!(commit.epoch(), epoch_before);
        prop_assert_eq!(commit.operations(), &[CommitOperation::AddMember(member)]);
        prop_assert!(group.is_member(&member));
        prop_assert_eq!(group.current_epoch(), epoch_before + 1);
    }

    #[test]
    fn key_schedule_lengths_are_correct(
        group_id in prop::collection::vec(any::<u8>(), 1..32),
        initiator_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let runtime = rt();
        let group = runtime
            .block_on(MlsGroup::new(group_id, AgentId(initiator_bytes)))
            .unwrap();
        let schedule = MlsKeySchedule::from_group(&group).unwrap();

        prop_assert_eq!(schedule.encryption_key().len(), 32);
        prop_assert_eq!(schedule.base_nonce().len(), 12);
    }
}
