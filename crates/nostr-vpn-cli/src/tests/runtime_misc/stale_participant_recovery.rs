use super::*;

#[test]
fn cooldown_is_enforced() {
    let mut last_restart_at = None;

    assert!(begin_fips_recovery(&mut last_restart_at, 1_000));
    assert_eq!(last_restart_at, Some(1_000));
    assert!(!begin_fips_recovery(
        &mut last_restart_at,
        1_000 + FIPS_RECOVERY_COOLDOWN_SECS - 1
    ));
    assert!(begin_fips_recovery(
        &mut last_restart_at,
        1_000 + FIPS_RECOVERY_COOLDOWN_SECS
    ));
    assert!(begin_fips_recovery(&mut last_restart_at, 900));
}

#[test]
fn peer_path_refresh_does_not_delay_local_endpoint_recovery() {
    let mut cooldowns = FipsRecoveryCooldowns::default();
    assert!(cooldowns.begin_path_refresh(1_000));
    assert!(!cooldowns.begin_path_refresh(1_045));
    assert!(cooldowns.begin_endpoint_rebuild(1_045));

    // The old peer refresh cooldown expires before the rebuild cooldown.
    assert!(!cooldowns.begin_path_refresh(1_060));
    assert!(!cooldowns.begin_endpoint_rebuild(1_060));
    assert!(cooldowns.begin_path_refresh(1_045 + FIPS_RECOVERY_COOLDOWN_SECS));
    assert!(cooldowns.begin_endpoint_rebuild(1_045 + FIPS_RECOVERY_COOLDOWN_SECS));
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
