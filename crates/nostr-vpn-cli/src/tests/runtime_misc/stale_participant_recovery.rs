use super::*;

#[test]
fn cooldown_is_enforced() {
    let mut last_restart_at = None;

    assert!(fips_stale_participant_restart_due(
        &mut last_restart_at,
        1_000
    ));
    assert_eq!(last_restart_at, Some(1_000));
    assert!(!fips_stale_participant_restart_due(
        &mut last_restart_at,
        1_000 + FIPS_STALE_PARTICIPANT_RESTART_COOLDOWN_SECS - 1
    ));
    assert!(fips_stale_participant_restart_due(
        &mut last_restart_at,
        1_000 + FIPS_STALE_PARTICIPANT_RESTART_COOLDOWN_SECS
    ));
    assert!(fips_stale_participant_restart_due(
        &mut last_restart_at,
        900
    ));
}

#[test]
fn carrier_rebind_requires_every_peer_path_to_fail() {
    let stale = vec!["a".to_string()];
    let mut peers = vec![pending_fips_peer("a"), pending_fips_peer("b")];

    assert!(fips_stale_participant_carrier_rebind_required(
        &peers, &stale
    ));

    peers[1].connected = true;
    assert!(!fips_stale_participant_carrier_rebind_required(
        &peers, &stale
    ));
    assert!(!fips_stale_participant_carrier_rebind_required(&peers, &[]));
    peers[1].connected = false;
    let mut seller = pending_fips_peer("public-paid-seller");
    seller.connected = true;
    peers.push(seller);
    assert!(
        !fips_stale_participant_carrier_rebind_required(&peers, &stale),
        "a private device going offline must not rebind a working paid connection"
    );
}
