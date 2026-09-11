use std::str::FromStr;

use super::super::keysets_and_amounts::KeysetInfo;
use super::*;
use cashu::nuts::{CurrencyUnit, Id, Keys};

fn create_test_params(input_fee_ppk: u64, power: u64) -> ChannelParameters {
    // Create a simple keyset with powers of the given base for testing
    // power=2 gives powers-of-2: 1, 2, 4, 8, 16, ...
    // power=10 gives powers-of-10: 1, 10, 100, 1000, ...
    use std::collections::BTreeMap;

    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();

    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let mint_secret = SecretKey::generate();
    let mint_pubkey = mint_secret.public_key();

    let mut keys_map = BTreeMap::new();
    for i in 0..10 {
        let amount = Amount::from(power.pow(i as u32));
        keys_map.insert(amount, mint_pubkey);
    }
    let keys = Keys::new(keys_map);

    // Create keyset info
    let keyset_id = Id::from_bytes(&[0; 8]).unwrap();
    let keyset_info = KeysetInfo::new(keyset_id, CurrencyUnit::Sat, keys, input_fee_ppk, None);

    let capacity = 1000;
    let maximum_amount = 100_000;
    let funding_token_amount =
        ChannelParameters::get_minimum_funding_token_amount(capacity, &keyset_info, maximum_amount)
            .unwrap();

    ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "local".to_string(),
        CurrencyUnit::Sat,
        capacity,
        funding_token_amount,
        0, // expiry_timestamp
        0, // setup_timestamp
        keyset_info,
        maximum_amount,
        &alice_secret,
    )
    .unwrap()
}

#[test]
fn test_count_by_amount() {
    let params = create_test_params(0, 2); // Powers of 2, no fees
    let max_amount = params.maximum_amount_for_one_output;
    let keyset_info = &params.keyset_info;

    // Test a specific example: 42 = 32 + 8 + 2
    let amounts = OrderedListOfAmounts::from_target(42, max_amount, keyset_info).unwrap();
    let count_map = &amounts.count_by_amount;

    // Should have 1×32, 1×8, 1×2
    assert_eq!(count_map.get(&32), Some(&1));
    assert_eq!(count_map.get(&8), Some(&1));
    assert_eq!(count_map.get(&2), Some(&1));
    assert_eq!(count_map.len(), 3);

    // Verify forward iteration gives us smallest-to-largest (BTreeMap natural order)
    let forward: Vec<(u64, usize)> = count_map.iter().map(|(&k, &v)| (k, v)).collect();
    assert_eq!(forward, vec![(2, 1), (8, 1), (32, 1)]);

    // Test another: 15 = 8 + 4 + 2 + 1
    let amounts = OrderedListOfAmounts::from_target(15, max_amount, keyset_info).unwrap();
    let count_map = &amounts.count_by_amount;
    assert_eq!(count_map.get(&8), Some(&1));
    assert_eq!(count_map.get(&4), Some(&1));
    assert_eq!(count_map.get(&2), Some(&1));
    assert_eq!(count_map.get(&1), Some(&1));
    assert_eq!(count_map.len(), 4);

    // Verify forward iteration (smallest-first)
    let forward: Vec<(u64, usize)> = count_map.iter().map(|(&k, &v)| (k, v)).collect();
    assert_eq!(forward, vec![(1, 1), (2, 1), (4, 1), (8, 1)]);

    // Test with multiple of same amount: 7 = 4 + 2 + 1
    let amounts = OrderedListOfAmounts::from_target(7, max_amount, keyset_info).unwrap();
    let count_map = &amounts.count_by_amount;
    assert_eq!(count_map.get(&4), Some(&1));
    assert_eq!(count_map.get(&2), Some(&1));
    assert_eq!(count_map.get(&1), Some(&1));

    let forward: Vec<(u64, usize)> = count_map.iter().map(|(&k, &v)| (k, v)).collect();
    assert_eq!(forward, vec![(1, 1), (2, 1), (4, 1)]);
}

/// Create test params with a specific expiry_timestamp (for funding token tests)
fn create_test_params_with_expiry(
    input_fee_ppk: u64,
    power: u64,
    expiry_timestamp: u64,
) -> ChannelParameters {
    use std::collections::BTreeMap;

    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();

    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let mint_secret = SecretKey::generate();
    let mint_pubkey = mint_secret.public_key();

    let mut keys_map = BTreeMap::new();
    for i in 0..10 {
        let amount = Amount::from(power.pow(i as u32));
        keys_map.insert(amount, mint_pubkey);
    }
    let keys = Keys::new(keys_map);

    let keyset_id = Id::from_bytes(&[0; 8]).unwrap();
    let keyset_info = KeysetInfo::new(keyset_id, CurrencyUnit::Sat, keys, input_fee_ppk, None);

    let capacity = 1000;
    let maximum_amount = 100_000;
    let funding_token_amount =
        ChannelParameters::get_minimum_funding_token_amount(capacity, &keyset_info, maximum_amount)
            .unwrap();

    ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "local".to_string(),
        CurrencyUnit::Sat,
        capacity,
        funding_token_amount,
        expiry_timestamp, // expiry_timestamp (configurable)
        0,                // setup_timestamp
        keyset_info,
        maximum_amount,
        &alice_secret,
    )
    .unwrap()
}

#[test]
fn test_funding_token_uses_correct_blinded_pubkeys() {
    // Test that funding token P2PK secret contains the correct blinded pubkeys:
    // - "data" field: Alice's blinded pubkey (sender_stage1)
    // - "pubkeys" tag: Charlie's blinded pubkey (receiver_stage1) for 2-of-2
    // - refund "pubkeys" tag: Alice's REFUND blinded pubkey (sender_stage1_refund)

    // Use a future expiry_timestamp to pass Conditions::new() validation
    let future_expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600; // 1 hour in the future

    let params = create_test_params_with_expiry(0, 2, future_expiry);

    // Get the expected blinded pubkeys
    let expected_alice_blinded = params
        .get_sender_blinded_pubkey_for_stage1()
        .expect("Failed to get sender blinded pubkey");
    let expected_charlie_blinded = params
        .get_receiver_blinded_pubkey_for_stage1()
        .expect("Failed to get receiver blinded pubkey");
    let expected_alice_refund = params
        .get_sender_blinded_pubkey_for_stage1_refund()
        .expect("Failed to get refund blinded pubkey");

    println!(
        "Expected Alice blinded (data):   {}",
        expected_alice_blinded.to_hex()
    );
    println!(
        "Expected Charlie blinded (2of2): {}",
        expected_charlie_blinded.to_hex()
    );
    println!(
        "Expected Alice refund:           {}",
        expected_alice_refund.to_hex()
    );

    // Verify all three are distinct
    assert_ne!(
        expected_alice_blinded.to_hex(),
        expected_charlie_blinded.to_hex(),
        "Alice and Charlie blinded pubkeys should differ"
    );
    assert_ne!(
        expected_alice_blinded.to_hex(),
        expected_alice_refund.to_hex(),
        "Alice blinded and refund pubkeys should differ"
    );
    assert_ne!(
        expected_charlie_blinded.to_hex(),
        expected_alice_refund.to_hex(),
        "Charlie blinded and Alice refund pubkeys should differ"
    );

    // Create a funding output
    let funding_output = params
        .create_deterministic_output_with_blinding("funding", 64, 0)
        .expect("Failed to create funding output");

    // Parse the secret as JSON to inspect the P2PK structure
    let secret_str = funding_output.secret.to_string();
    println!("Funding secret: {}", secret_str);

    let secret_json: serde_json::Value =
        serde_json::from_str(&secret_str).expect("Failed to parse secret as JSON");

    // Structure is: ["P2PK", {"nonce": "...", "data": "pubkey_hex", "tags": [...]}]
    let inner = secret_json
        .as_array()
        .expect("Secret should be an array")
        .get(1)
        .expect("Secret should have inner object");

    // Check "data" field contains Alice's blinded pubkey
    let data_pubkey = inner["data"]
        .as_str()
        .expect("data field should be a string");
    assert_eq!(
        data_pubkey,
        expected_alice_blinded.to_hex(),
        "data field should contain Alice's blinded pubkey"
    );
    println!("✓ data field contains Alice's blinded pubkey");

    // Parse tags to find pubkeys and refund keys
    let tags = inner["tags"].as_array().expect("tags should be an array");

    // Find the "pubkeys" tag (Charlie's key for 2-of-2)
    let pubkeys_tag = tags
        .iter()
        .find(|tag| {
            tag.as_array()
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                == Some("pubkeys")
        })
        .expect("Should have pubkeys tag");

    let receiver_pubkey_in_tag = pubkeys_tag
        .as_array()
        .and_then(|arr| arr.get(1))
        .and_then(|v| v.as_str())
        .expect("pubkeys tag should have a pubkey value");

    assert_eq!(
        receiver_pubkey_in_tag,
        expected_charlie_blinded.to_hex(),
        "pubkeys tag should contain Charlie's blinded pubkey"
    );
    println!("✓ pubkeys tag contains Charlie's blinded pubkey");

    // Find the "refund" tag (Alice's refund key)
    let refund_tag = tags
        .iter()
        .find(|tag| {
            tag.as_array()
                .and_then(|arr| arr.first())
                .and_then(|v| v.as_str())
                == Some("refund")
        })
        .expect("Should have refund tag");

    let alice_refund_in_tag = refund_tag
        .as_array()
        .and_then(|arr| arr.get(1))
        .and_then(|v| v.as_str())
        .expect("refund tag should have a pubkey value");

    assert_eq!(
        alice_refund_in_tag,
        expected_alice_refund.to_hex(),
        "refund tag should contain Alice's REFUND blinded pubkey (different tweak)"
    );
    println!("✓ refund tag contains Alice's refund blinded pubkey");

    // Verify it's NOT the same as the data field (different tweak)
    assert_ne!(
        data_pubkey, alice_refund_in_tag,
        "data and refund pubkeys should use different tweaks"
    );
    println!("✓ data and refund pubkeys are distinct (different tweaks)");
}

#[test]
fn test_funding_outputs_are_ascending_by_amount() {
    // Funding outputs should be in ascending order of amount per NUT-03 recommendation.
    // Use powers-of-2 keyset so e.g. 1000 = 512 + 256 + 128 + 64 + 32 + 8
    let future_expiry = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        + 3600;
    let params = create_test_params_with_expiry(0, 2, future_expiry);
    let funding_outputs = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        params.funding_token_amount,
        params.clone(),
    )
    .expect("funding outputs");

    let blinded_messages = funding_outputs
        .get_blinded_messages(None)
        .expect("get_blinded_messages");

    assert!(
        blinded_messages.len() > 1,
        "need multiple outputs to test ordering"
    );

    let amounts: Vec<u64> = blinded_messages
        .iter()
        .map(|bm| u64::from(bm.amount))
        .collect();

    let amounts_text = amounts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    for i in 1..amounts.len() {
        assert!(
            amounts[i] >= amounts[i - 1],
            "funding outputs not in ascending order: {amounts_text}",
        );
    }
    println!("funding outputs are ascending: {amounts_text}");
}

#[test]
fn test_commitment_outputs_are_ascending_receiver_before_sender() {
    // Commitment swap outputs should be ascending by amount,
    // with receiver (Charlie) before sender (Alice) for same amounts.
    // Use powers-of-10 keyset to get repeated amounts (e.g. five 100-sat outputs).
    let params = create_test_params(0, 10);
    let balance = params.capacity / 2; // split roughly evenly

    let commitment = CommitmentOutputs::for_balance(balance, &params).expect("commitment outputs");

    // We need dummy funding proofs to call create_swap_request.
    // Build them from the funding outputs structure.
    let funding = DeterministicOutputsForOneContext::new(
        "funding".to_string(),
        params.funding_token_amount,
        params.clone(),
    )
    .expect("funding outputs");

    // Create minimal dummy proofs with correct amounts
    let dummy_proofs: Vec<cashu::nuts::Proof> = funding
        .ordered_amounts
        .iter_smallest_first()
        .flat_map(|(&amount, &count)| {
            (0..count).map(move |_| cashu::nuts::Proof {
                amount: Amount::from(amount),
                keyset_id: params.keyset_info.keyset_id,
                secret: Secret::new("dummy".to_string()),
                c: cashu::nuts::PublicKey::from_str(
                    "02a9acc1e48c25eeeb9289b5031cc57da9fe72f3fe2861d264bdc074209b107ba2",
                )
                .unwrap(),
                witness: None,
                dleq: None,
                p2pk_e: None,
            })
        })
        .collect();

    let swap_request = commitment
        .create_swap_request(dummy_proofs, None)
        .expect("create_swap_request");

    let outputs = swap_request.outputs();
    let output_amounts: Vec<u64> = outputs.iter().map(|bm| u64::from(bm.amount)).collect();

    // 1. Verify ascending order
    let output_amounts_text = output_amounts
        .iter()
        .map(u64::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    for i in 1..output_amounts.len() {
        assert!(
            output_amounts[i] >= output_amounts[i - 1],
            "commitment outputs not in ascending order: {output_amounts_text}",
        );
    }
    println!("commitment outputs are ascending: {output_amounts_text}");

    // 2. Verify receiver comes before sender for same amounts.
    // We can check this by getting each party's blinded messages separately
    // and confirming the interleaved order matches: for each amount group,
    // receiver outputs appear first.
    let receiver_msgs = commitment
        .receiver_outputs
        .get_blinded_messages(None)
        .expect("receiver msgs");
    let sender_msgs = commitment
        .sender_outputs
        .get_blinded_messages(None)
        .expect("sender msgs");

    // Build a set of B_ values (blinded points) for each party
    let receiver_b_set: std::collections::HashSet<String> = receiver_msgs
        .iter()
        .map(|bm| format!("{:?}", bm.blinded_secret))
        .collect();
    let sender_b_set: std::collections::HashSet<String> = sender_msgs
        .iter()
        .map(|bm| format!("{:?}", bm.blinded_secret))
        .collect();

    // Walk through the combined outputs grouped by amount.
    // Within each amount group, all receiver outputs should precede all sender outputs.
    let mut i = 0;
    while i < outputs.len() {
        let current_amount = u64::from(outputs[i].amount);
        let group_start = i;

        // Collect the group of outputs with this amount
        while i < outputs.len() && u64::from(outputs[i].amount) == current_amount {
            i += 1;
        }

        // Within this group, check that all receiver outputs come before sender outputs
        let mut seen_sender = false;
        for (offset, output) in outputs[group_start..i].iter().enumerate() {
            let j = group_start + offset;
            let b_key = format!("{:?}", output.blinded_secret);
            let is_receiver = receiver_b_set.contains(&b_key);
            let is_sender = sender_b_set.contains(&b_key);

            if is_receiver {
                assert!(
                    !seen_sender,
                    "receiver output at position {} follows a sender output for amount {}",
                    j, current_amount
                );
            }
            if is_sender {
                seen_sender = true;
            }

            // At least one should match (unless the amount only belongs to one party)
            assert!(
                is_receiver || is_sender,
                "output at position {} doesn't match receiver or sender for amount {}",
                j,
                current_amount
            );
        }
    }
    println!("✓ receiver outputs precede sender outputs within each amount group");
}
