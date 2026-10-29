impl AppConfig {
    pub fn active_network_has_confirmed_local_identity(&self) -> bool {
        let Some(network) = self.active_network_opt() else {
            return false;
        };
        self.network_has_confirmed_local_identity(&network.id)
    }

    pub fn network_has_confirmed_local_identity(&self, network_id: &str) -> bool {
        let Some(network) = self.network_by_id(network_id) else {
            return false;
        };
        let Ok(own_pubkey) = self.own_nostr_pubkey_hex() else {
            return false;
        };

        local_identity_was_confirmed(network, &own_pubkey)
    }

    pub fn shared_network_roster(&self, network_id: &str) -> Result<SharedNetworkRoster> {
        let network = self
            .network_by_id(network_id)
            .ok_or_else(|| anyhow::anyhow!("network not found"))?;
        let mut devices = network.devices.clone();
        if let Ok(own_pubkey) = self.own_nostr_pubkey_hex() {
            devices.push(own_pubkey);
        }
        devices.sort();
        devices.dedup();

        let mut admins = network.admins.clone();
        admins.sort();
        admins.dedup();

        let own_pubkey = self.own_nostr_pubkey_hex().ok();
        let mut alias_keys = devices.clone();
        alias_keys.extend(admins.iter().cloned());
        alias_keys.sort();
        alias_keys.dedup();
        let aliases = alias_keys
            .into_iter()
            .filter_map(|member| {
                let alias = if own_pubkey.as_deref() == Some(member.as_str()) {
                    self.self_magic_dns_label()
                } else {
                    self.peer_alias(&member)
                }?;
                Some((member, alias))
            })
            .collect::<HashMap<_, _>>();

        Ok(SharedNetworkRoster {
            id: network.id.clone(),
            network_id: normalize_runtime_network_id(&network.network_id),
            name: network.name.clone(),
            devices,
            admins,
            aliases,
            updated_at: network.shared_roster_updated_at,
            signed_by: network.shared_roster_signed_by.clone(),
        })
    }

    pub fn apply_admin_signed_shared_roster(
        &mut self,
        update: AdminSignedSharedRosterUpdate,
    ) -> Result<bool> {
        let AdminSignedSharedRosterUpdate {
            network_id,
            network_name,
            devices,
            admins,
            aliases,
            signed_at,
            signed_by,
            artifact_hash,
        } = update;

        let normalized_network_id = normalize_runtime_network_id(&network_id);
        if normalized_network_id.is_empty() {
            return Ok(false);
        }

        let normalized_signed_by = normalize_nostr_pubkey(&signed_by)?;
        let own_pubkey = self.own_nostr_pubkey_hex().ok();
        let now = current_unix_timestamp();
        if signed_at > now.saturating_add(MAX_SHARED_ROSTER_FUTURE_SECS) {
            return Err(anyhow::anyhow!(
                "shared roster timestamp is too far in the future"
            ));
        }

        let Some(network_index) = self.networks.iter().position(|network| {
            normalize_runtime_network_id(&network.network_id) == normalized_network_id
        }) else {
            return Ok(false);
        };

        {
            let network = &self.networks[network_index];
            if !network
                .admins
                .iter()
                .any(|admin| admin == &normalized_signed_by)
            {
                return Ok(false);
            }
            if !signed_roster_artifact_wins(
                network.shared_roster_updated_at,
                &network.shared_roster_artifact_hash,
                signed_at,
                &artifact_hash,
            ) {
                return Ok(false);
            }
        }

        let own_in_shared_roster = own_pubkey.as_deref().is_none_or(|own_pubkey| {
            devices
                .iter()
                .chain(admins.iter())
                .filter_map(|member| normalize_nostr_pubkey(member).ok())
                .any(|member| member == own_pubkey)
        });
        let own_in_previous_roster = own_pubkey.as_deref().is_some_and(|own_pubkey| {
            local_identity_was_confirmed(&self.networks[network_index], own_pubkey)
        });

        if own_pubkey.is_some() && own_in_previous_roster && !own_in_shared_roster {
            self.networks.remove(network_index);
            self.normalize_selected_exit_node();
            self.normalize_peer_aliases();
            return Ok(true);
        }

        let own_join_completed =
            own_pubkey.is_some() && !own_in_previous_roster && own_in_shared_roster;
        if own_join_completed {
            self.pending_nostr_join_request = None;
        }
        let mut devices = if own_in_shared_roster {
            normalize_shared_roster_devices(devices, own_pubkey.as_deref())?
        } else {
            Vec::new()
        };
        let removed_devices = self.networks[network_index]
            .removed_devices
            .iter()
            .filter_map(|member| normalize_nostr_pubkey(member).ok())
            .collect::<HashSet<_>>();
        let suppressed_stale_devices = devices
            .iter()
            .any(|device| removed_devices.contains(device));
        devices.retain(|device| !removed_devices.contains(device));
        let network = &mut self.networks[network_index];
        let mut admins =
            normalize_network_admins(admins, own_pubkey.as_deref(), &network.join_request_admin);
        let suppressed_stale_admins = admins
            .iter()
            .any(|admin| removed_devices.contains(admin));
        admins.retain(|admin| !removed_devices.contains(admin));
        if admins.is_empty() {
            return Err(anyhow::anyhow!(
                "shared roster must include at least one admin"
            ));
        }

        network.devices = devices;
        network.admins = admins;
        if !network_name.trim().is_empty() {
            network.name = network_name.trim().to_string();
        }
        if !network
            .admins
            .iter()
            .any(|admin| admin == &network.join_request_admin)
        {
            network.join_request_admin = normalized_signed_by.clone();
        }
        network.shared_roster_updated_at = signed_at;
        network.shared_roster_signed_by = normalized_signed_by;
        network.shared_roster_artifact_hash = artifact_hash;
        if own_in_shared_roster {
            network.local_identity_confirmation_pending = false;
        }
        if (suppressed_stale_devices || suppressed_stale_admins)
            && own_pubkey
                .as_deref()
                .is_some_and(|own| network.admins.iter().any(|admin| admin == own))
        {
            network.shared_roster_updated_at =
                next_shared_roster_updated_at(network.shared_roster_updated_at);
            network.shared_roster_signed_by = own_pubkey.clone().unwrap_or_default();
            network.shared_roster_artifact_hash.clear();
        }
        network.outbound_join_request = if own_join_completed {
            None
        } else {
            normalize_outbound_join_request(
                network.outbound_join_request.take(),
                &network.devices,
            )
        };
        network.inbound_join_requests = normalize_inbound_join_requests(
            std::mem::take(&mut network.inbound_join_requests),
            &network.devices,
        );

        let mut allowed_members = network.devices.clone();
        allowed_members.extend(network.admins.iter().cloned());
        if own_in_shared_roster && let Some(own_pubkey) = &own_pubkey {
            allowed_members.push(own_pubkey.clone());
        }
        allowed_members.sort();
        allowed_members.dedup();
        let allowed_members = allowed_members.into_iter().collect::<HashSet<_>>();
        for (participant, alias) in aliases {
            let Ok(normalized_participant) = normalize_nostr_pubkey(&participant) else {
                continue;
            };
            if !allowed_members.contains(&normalized_participant) {
                continue;
            }
            let Some(normalized_alias) = normalize_magic_dns_label(&alias) else {
                continue;
            };
            self.peer_aliases.insert(
                npub_for_pubkey_hex(&normalized_participant),
                normalized_alias,
            );
        }
        self.normalize_selected_exit_node();
        self.normalize_peer_aliases();
        if own_join_completed {
            self.ensure_pending_nostr_join_request(now)?;
        }
        Ok(true)
    }

    pub fn apply_verified_admin_signed_shared_roster(
        &mut self,
        signed_roster: &SignedRoster,
    ) -> Result<bool> {
        signed_roster.verify()?;
        let network_id = signed_roster.network_id()?;
        let roster = signed_roster.roster()?;
        let signed_by = signed_roster.signer_pubkey_hex()?;
        self.apply_admin_signed_shared_roster(AdminSignedSharedRosterUpdate {
            network_id,
            network_name: roster.network_name,
            devices: roster.devices,
            admins: roster.admins,
            aliases: roster.aliases,
            signed_at: roster.signed_at,
            signed_by,
            artifact_hash: signed_roster.artifact_hash(),
        })
    }

}

fn local_identity_was_confirmed(network: &NetworkConfig, own_pubkey: &str) -> bool {
    if network.local_identity_confirmation_pending {
        return false;
    }
    if network
        .devices
        .iter()
        .chain(network.admins.iter())
        .filter_map(|member| normalize_nostr_pubkey(member).ok())
        .any(|member| member == own_pubkey)
    {
        return true;
    }

    network.outbound_join_request.is_none()
        && network.shared_roster_updated_at > 0
        && !network.shared_roster_signed_by.is_empty()
}
