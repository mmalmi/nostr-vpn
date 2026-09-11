use super::*;

#[test]
fn test_json_roundtrip_preserves_channel_id() {
    // Create keypairs for Alice and Charlie
    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    // Create a keyset_info for testing (powers of 2 up to 64, with 100 ppk fee)
    let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

    // Compute the minimum funding_token_amount for the desired capacity
    let funding_token_amount =
        ChannelParameters::get_minimum_funding_token_amount(1000, &keyset_info, 64)
            .expect("Failed to compute funding token amount");

    // Create channel parameters (as Alice)
    let original_params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "https://testmint.cash".to_string(),
        CurrencyUnit::Sat,
        1000, // capacity
        funding_token_amount,
        1700000000, // expiry_timestamp
        1699999000, // setup_timestamp
        keyset_info.clone(),
        64, // maximum_amount_for_one_output
        &alice_secret,
    )
    .expect("Failed to create original params");

    // Get the channel ID and JSON
    let original_channel_id = original_params.get_channel_id();
    let json = original_params.get_channel_id_params_json();

    println!("Channel ID: {}", original_channel_id);
    println!("JSON: {}", json);

    // Recreate from JSON (as Charlie this time, to also test ECDH works both ways)
    let reconstructed_params =
        ChannelParameters::from_json_with_secret_key(&json, keyset_info, &charlie_secret)
            .expect("Failed to reconstruct params from JSON");

    let reconstructed_channel_id = reconstructed_params.get_channel_id();

    println!("Reconstructed Channel ID: {}", reconstructed_channel_id);

    // Verify channel secrets match (ECDH is symmetric, so both sides derive the same result)
    assert_eq!(
        original_params.channel_secret, reconstructed_params.channel_secret,
        "Channel secrets should match (ECDH is symmetric)"
    );

    // Assert channel IDs match
    assert_eq!(
        original_channel_id, reconstructed_channel_id,
        "Channel IDs should match after JSON roundtrip"
    );
}

#[test]
fn test_p2bk_blinded_pubkey_consistency() {
    // Test that blinded pubkeys are computed consistently regardless of which
    // party creates the ChannelParameters (Alice or Charlie)

    // Create keypairs for Alice and Charlie
    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    // Create keyset_info
    let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

    let funding_token_amount =
        ChannelParameters::get_minimum_funding_token_amount(1000, &keyset_info, 64)
            .expect("Failed to compute funding token amount");

    // Alice creates params using her secret key
    let alice_params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "https://testmint.cash".to_string(),
        CurrencyUnit::Sat,
        1000, // capacity
        funding_token_amount,
        1700000000,
        1699999000,
        keyset_info.clone(),
        64,
        &alice_secret,
    )
    .expect("Failed to create Alice's params");

    // Charlie recreates params from JSON using his secret key
    let json = alice_params.get_channel_id_params_json();
    let charlie_params =
        ChannelParameters::from_json_with_secret_key(&json, keyset_info, &charlie_secret)
            .expect("Failed to create Charlie's params");

    // Verify channel secrets match (ECDH symmetry)
    assert_eq!(
        alice_params.channel_secret, charlie_params.channel_secret,
        "Channel secrets should match"
    );

    // Verify blinded sender pubkey is the same
    let alice_blinded_sender = alice_params
        .get_sender_blinded_pubkey_for_stage1()
        .expect("Alice failed to get blinded sender pubkey");
    let charlie_blinded_sender = charlie_params
        .get_sender_blinded_pubkey_for_stage1()
        .expect("Charlie failed to get blinded sender pubkey");
    assert_eq!(
        alice_blinded_sender.to_hex(),
        charlie_blinded_sender.to_hex(),
        "Blinded sender pubkeys should match"
    );

    // Verify blinded receiver pubkey is the same
    let alice_blinded_receiver = alice_params
        .get_receiver_blinded_pubkey_for_stage1()
        .expect("Alice failed to get blinded receiver pubkey");
    let charlie_blinded_receiver = charlie_params
        .get_receiver_blinded_pubkey_for_stage1()
        .expect("Charlie failed to get blinded receiver pubkey");
    assert_eq!(
        alice_blinded_receiver.to_hex(),
        charlie_blinded_receiver.to_hex(),
        "Blinded receiver pubkeys should match"
    );

    println!(
        "Alice's blinded sender pubkey: {}",
        alice_blinded_sender.to_hex()
    );
    println!(
        "Charlie's blinded sender pubkey: {}",
        charlie_blinded_sender.to_hex()
    );
    println!(
        "Alice's blinded receiver pubkey: {}",
        alice_blinded_receiver.to_hex()
    );
    println!(
        "Charlie's blinded receiver pubkey: {}",
        charlie_blinded_receiver.to_hex()
    );
}

#[test]
fn test_p2bk_signature_roundtrip() {
    use bitcoin::secp256k1::Message;
    use cashu::SECP256K1;

    // Create keypairs for Alice and Charlie
    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    // Create keyset_info
    let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

    let funding_token_amount =
        ChannelParameters::get_minimum_funding_token_amount(1000, &keyset_info, 64)
            .expect("Failed to compute funding token amount");

    // Alice creates params
    let alice_params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "https://testmint.cash".to_string(),
        CurrencyUnit::Sat,
        1000, // capacity
        funding_token_amount,
        1700000000,
        1699999000,
        keyset_info.clone(),
        64,
        &alice_secret,
    )
    .expect("Failed to create Alice's params");

    // Alice gets her blinded secret key and signs a message
    let blinded_secret = alice_params
        .get_sender_blinded_secret_key_for_stage1(&alice_secret)
        .expect("Failed to get blinded secret");

    let test_msg = b"test message to sign";
    let msg_hash = bitcoin::hashes::sha256::Hash::hash(test_msg);
    let msg = Message::from_digest_slice(msg_hash.as_ref()).unwrap();

    // Get the secp256k1 keypair for signing
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&SECP256K1, &blinded_secret);
    let signature = SECP256K1.sign_schnorr(&msg, &keypair);

    println!("Message: {}", hex::encode(msg_hash.to_byte_array()));
    println!("Signature: {}", hex::encode(signature.serialize()));

    // Charlie recreates params and verifies
    let json = alice_params.get_channel_id_params_json();
    let charlie_params =
        ChannelParameters::from_json_with_secret_key(&json, keyset_info, &charlie_secret)
            .expect("Failed to create Charlie's params");

    // Charlie gets Alice's blinded pubkey
    let blinded_pubkey = charlie_params
        .get_sender_blinded_pubkey_for_stage1()
        .expect("Failed to get blinded sender pubkey");

    println!("Blinded pubkey: {}", blinded_pubkey.to_hex());

    // Charlie verifies the signature
    let verify_result = blinded_pubkey.verify(test_msg, &signature);
    assert!(
        verify_result.is_ok(),
        "Signature verification failed: {:?}",
        verify_result
    );
    println!("Signature verified successfully!");
}

#[test]
fn test_stage2_ephemeral_shared_secret_matches_role_secret() {
    // Create keypairs for Alice and Charlie
    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    // Create keyset_info
    let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

    let funding_token_amount =
        ChannelParameters::get_minimum_funding_token_amount(1000, &keyset_info, 64)
            .expect("Failed to compute funding token amount");

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "https://testmint.cash".to_string(),
        CurrencyUnit::Sat,
        1000, // capacity
        funding_token_amount,
        1700000000,
        1699999000,
        keyset_info,
        64,
        &alice_secret,
    )
    .expect("Failed to create channel params");

    let sender_info = params
        .stage2_tweak_info_for_role(Stage2Role::Sender, 64, 0)
        .expect("Failed to derive sender stage2 tweak info");
    let sender_shared_from_alice = ChannelParameters::derive_nut28_shared_secret_x(
        &sender_info.ephemeral_pubkey,
        &alice_secret,
    )
    .expect("Failed to derive sender raw NUT-28 shared secret");
    assert_eq!(
        sender_shared_from_alice, sender_info.ephemeral_shared_secret_x,
        "Alice should derive the same shared secret x for sender_stage2"
    );
    #[cfg(feature = "wallet")]
    {
        let sender_kdf =
            cashu::nuts::nut28::ecdh_kdf(&alice_secret, &sender_info.ephemeral_pubkey, 0)
                .expect("Failed to derive sender NUT-28 scalar");
        assert_eq!(
            sender_kdf.secret_bytes(),
            sender_info.stage2_tweak_scalar.to_be_bytes(),
            "Alice should derive the same NUT-28 scalar for sender_stage2"
        );
    }

    let receiver_info = params
        .stage2_tweak_info_for_role(Stage2Role::Receiver, 64, 0)
        .expect("Failed to derive receiver stage2 tweak info");
    let receiver_shared_from_charlie = ChannelParameters::derive_nut28_shared_secret_x(
        &receiver_info.ephemeral_pubkey,
        &charlie_secret,
    )
    .expect("Failed to derive receiver raw NUT-28 shared secret");
    assert_eq!(
        receiver_shared_from_charlie, receiver_info.ephemeral_shared_secret_x,
        "Charlie should derive the same shared secret x for receiver_stage2"
    );
    #[cfg(feature = "wallet")]
    {
        let receiver_kdf =
            cashu::nuts::nut28::ecdh_kdf(&charlie_secret, &receiver_info.ephemeral_pubkey, 0)
                .expect("Failed to derive receiver NUT-28 scalar");
        assert_eq!(
            receiver_kdf.secret_bytes(),
            receiver_info.stage2_tweak_scalar.to_be_bytes(),
            "Charlie should derive the same NUT-28 scalar for receiver_stage2"
        );
    }
}

#[test]
fn test_refund_blinded_pubkey_differs_from_sender() {
    // Test that the refund blinded pubkey uses a different tweak than the sender pubkey

    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

    let funding_token_amount =
        ChannelParameters::get_minimum_funding_token_amount(1000, &keyset_info, 64)
            .expect("Failed to compute funding token amount");

    let params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "https://testmint.cash".to_string(),
        CurrencyUnit::Sat,
        1000, // capacity
        funding_token_amount,
        1700000000,
        1699999000,
        keyset_info,
        64,
        &alice_secret,
    )
    .expect("Failed to create params");

    // Get the three pubkeys
    let raw_alice = params.sender_pubkey;
    let blinded_sender = params
        .get_sender_blinded_pubkey_for_stage1()
        .expect("Failed to get sender blinded pubkey");
    let blinded_refund = params
        .get_sender_blinded_pubkey_for_stage1_refund()
        .expect("Failed to get refund blinded pubkey");

    println!("Raw Alice pubkey:      {}", raw_alice.to_hex());
    println!("Blinded sender pubkey: {}", blinded_sender.to_hex());
    println!("Blinded refund pubkey: {}", blinded_refund.to_hex());

    // All three should be different
    assert_ne!(
        raw_alice.to_hex(),
        blinded_sender.to_hex(),
        "Blinded sender should differ from raw Alice pubkey"
    );
    assert_ne!(
        raw_alice.to_hex(),
        blinded_refund.to_hex(),
        "Blinded refund should differ from raw Alice pubkey"
    );
    assert_ne!(
        blinded_sender.to_hex(),
        blinded_refund.to_hex(),
        "Blinded sender and refund should use different tweaks"
    );

    println!("✓ All three pubkeys are distinct");
}

#[test]
fn test_refund_signature_roundtrip() {
    use bitcoin::secp256k1::Message;
    use cashu::SECP256K1;

    // Test that signing with refund blinded key verifies against refund blinded pubkey

    let alice_secret = SecretKey::generate();
    let sender_pubkey = alice_secret.public_key();
    let charlie_secret = SecretKey::generate();
    let receiver_pubkey = charlie_secret.public_key();

    let keyset_info = mock_keyset_info(vec![1, 2, 4, 8, 16, 32, 64], 100);

    let funding_token_amount =
        ChannelParameters::get_minimum_funding_token_amount(1000, &keyset_info, 64)
            .expect("Failed to compute funding token amount");

    // Alice creates params
    let alice_params = ChannelParameters::new_with_secret_key(
        sender_pubkey,
        receiver_pubkey,
        "https://testmint.cash".to_string(),
        CurrencyUnit::Sat,
        1000, // capacity
        funding_token_amount,
        1700000000,
        1699999000,
        keyset_info.clone(),
        64,
        &alice_secret,
    )
    .expect("Failed to create Alice's params");

    // Alice gets her REFUND blinded secret key and signs a message
    let blinded_refund_secret = alice_params
        .get_sender_blinded_secret_key_for_stage1_refund(&alice_secret)
        .expect("Failed to get refund blinded secret");

    let test_msg = b"refund message to sign";
    let msg_hash = bitcoin::hashes::sha256::Hash::hash(test_msg);
    let msg = Message::from_digest_slice(msg_hash.as_ref()).unwrap();

    // Sign with refund blinded key
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&SECP256K1, &blinded_refund_secret);
    let signature = SECP256K1.sign_schnorr(&msg, &keypair);

    println!("Message: {}", hex::encode(msg_hash.to_byte_array()));
    println!("Signature: {}", hex::encode(signature.serialize()));

    // Charlie recreates params and verifies using REFUND blinded pubkey
    let json = alice_params.get_channel_id_params_json();
    let charlie_params =
        ChannelParameters::from_json_with_secret_key(&json, keyset_info, &charlie_secret)
            .expect("Failed to create Charlie's params");

    let blinded_refund_pubkey = charlie_params
        .get_sender_blinded_pubkey_for_stage1_refund()
        .expect("Failed to get refund blinded pubkey");

    println!("Refund blinded pubkey: {}", blinded_refund_pubkey.to_hex());

    // Verify the signature
    let verify_result = blinded_refund_pubkey.verify(test_msg, &signature);
    assert!(
        verify_result.is_ok(),
        "Refund signature verification failed: {:?}",
        verify_result
    );
    println!("✓ Refund signature verified successfully!");

    // Also verify that the WRONG pubkey (sender, not refund) fails
    let blinded_sender_pubkey = charlie_params
        .get_sender_blinded_pubkey_for_stage1()
        .expect("Failed to get sender blinded pubkey");

    let wrong_verify_result = blinded_sender_pubkey.verify(test_msg, &signature);
    assert!(
        wrong_verify_result.is_err(),
        "Signature should NOT verify against sender pubkey (wrong tweak)"
    );
    println!("✓ Signature correctly fails against sender pubkey (different tweak)");
}

#[test]
fn test_channel_id_derivation() {
    let alice_sk = SecretKey::generate();
    let charlie_sk = SecretKey::generate();
    let channel_secret = compute_channel_secret(&alice_sk, &charlie_sk.public_key());

    let keyset = mock_keyset_info(vec![1, 2, 4, 8, 16], 0);

    let params = ChannelParameters {
        sender_pubkey: alice_sk.public_key(),
        receiver_pubkey: charlie_sk.public_key(),
        mint: "https://mint.host".to_string(),
        unit: CurrencyUnit::Sat,
        capacity: 1000,
        funding_token_amount: 1000,
        maximum_amount_for_one_output: 64,
        setup_timestamp: 1700000000,
        expiry_timestamp: 1700003600,
        keyset_info: keyset,
        channel_secret,
    };

    let channel_id = params.get_channel_id();
    assert_eq!(channel_id.len(), 64);
    assert_eq!(channel_id, params.get_channel_id()); // Idempotent
}
