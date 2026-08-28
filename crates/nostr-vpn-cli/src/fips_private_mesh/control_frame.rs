fn control_frame_source_pubkey(
    mesh: &FipsMeshRuntime,
    source_peer: PeerIdentity,
    frame: &FipsControlFrame,
) -> Option<String> {
    mesh.participant_for_endpoint_node_addr(source_peer.node_addr().as_bytes())
        .or_else(|| {
            // Configured transit is intentionally outside the private roster,
            // but its authenticated link still needs Ping/Pong liveness.
            let allow_unknown = matches!(
                frame,
                FipsControlFrame::Ping { .. }
                    | FipsControlFrame::Pong { .. }
                    | FipsControlFrame::JoinRequest { .. }
                    | FipsControlFrame::JoinRoster { .. }
                    | FipsControlFrame::JoinRosterAck { .. }
            );
            #[cfg(feature = "paid-exit")]
            let allow_unknown =
                allow_unknown
                    || matches!(
                        frame,
                        FipsControlFrame::PaidRouteSessionOpen { .. }
                            | FipsControlFrame::PaidRoutePayment { .. }
                    );
            allow_unknown.then(|| hex::encode(source_peer.pubkey().serialize()))
        })
}

fn control_frame_destination_peer(
    mesh: &FipsMeshRuntime,
    peer_identities: &FipsPeerIdentityMap,
    participant: &str,
) -> Result<PeerIdentity> {
    let participant_key = participant_pubkey_bytes(participant);
    let endpoint_node_addr = match participant_key.as_ref() {
        Some(participant) => mesh.peer_endpoint_node_addr_for_participant_pubkey_bytes(participant),
        None => mesh.peer_endpoint_node_addr(participant),
    };
    if let Some(endpoint_node_addr) = endpoint_node_addr {
        if let Some(identity) = endpoint_identity_for_send(
            peer_identities,
            participant_key.as_ref(),
            &endpoint_node_addr,
        ) {
            return Ok(identity);
        }
        return Err(anyhow!(
            "missing FIPS control frame recipient identity for {participant}"
        ));
    }

    if let Some(identity) = participant_key
        .as_ref()
        .and_then(|participant| peer_identities.identity_for_participant_bytes(participant))
        .or_else(|| peer_identities.identity_for_participant(participant))
    {
        return Ok(identity);
    }
    control_frame_participant_identity(participant)
        .ok_or_else(|| anyhow!("invalid FIPS control frame recipient {participant}"))
}

fn control_frame_participant_identity(participant: &str) -> Option<PeerIdentity> {
    normalize_nostr_pubkey(participant)
        .ok()
        .and_then(|participant| PublicKey::parse(&participant).ok())
        .and_then(|pubkey| pubkey.to_bech32().ok())
        .and_then(|npub| PeerIdentity::from_npub(&npub).ok())
}
