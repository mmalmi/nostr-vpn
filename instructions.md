# Nostr VPN on StartOS

Open the web UI after the service starts. Create a private network, then use
each new device's signed join-request QR or link to approve phones, laptops,
or other Nostr VPN devices.

The package runs separate daemon and web-control processes. Both use the `main`
volume, which is included in StartOS backups.
