#!/usr/bin/env python3
"""Exercise real wallet/channel renewal inside the isolated Docker buyer."""
import json
import pathlib
import sys
import time
import urllib.request

store_path = pathlib.Path('/root/.config/nvpn/paid-routes.json')


def snapshot():
    store = json.loads(store_path.read_text())
    selected = store['selected_buyer_session_id']
    return store, selected, store['sessions'][selected]['session']


store, original, session = snapshot()
capacity_msat = session['payment']['capacity_sat'] * 1000
price = int(sys.argv[2])
# Deliver more than twice the original channel's entire capacity, without
# retrying failed requests or switching the buyer's Internet mode.
target_bytes = capacity_msat * 1_000_000_000 // price * 9 // 4 + 4 * 1024 * 1024
seen = {original}
delivered = 0
while delivered < target_bytes:
    size = min(512 * 1024, target_bytes - delivered)
    with urllib.request.urlopen(f'{sys.argv[1]}/down?bytes={size}', timeout=15) as response:
        body = response.read()
    assert len(body) == size, (len(body), size)
    delivered += size
    store, selected, _ = snapshot()
    seen.add(selected)
    time.sleep(0.2)
assert len(seen) >= 3, f'expected at least two channel renewals, observed {len(seen) - 1}'
print(f'Renewal: {delivered} bytes delivered without request failures across {len(seen)} channels', flush=True)

# A quiet but authenticated provider must remain selected beyond the old
# 60-second no-traffic failover threshold.
_, selected, _ = snapshot()
time.sleep(75)
store, after_idle, _ = snapshot()
assert after_idle == selected, 'idle traffic caused a provider/session switch'
with urllib.request.urlopen(f'{sys.argv[1]}/down?bytes=32768', timeout=15) as response:
    assert len(response.read()) == 32768
for previous in seen - {selected}:
    payment = store['sessions'][previous]['session']['payment']
    channel = store['channels'][payment['channel_id']]
    assert channel['status'] in ('closing', 'closed'), f'old channel left open: {channel["status"]}'
    assert payment['paid_msat'] <= payment['capacity_sat'] * 1000
print('Renewal: old channels settled within capacity; idle provider stayed selected and resumed traffic', flush=True)
