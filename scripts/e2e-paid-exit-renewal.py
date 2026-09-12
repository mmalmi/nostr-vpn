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
deadline = time.monotonic() + 180
# A resumed Manual channel may be smaller than Automatic's renewal. Require
# two observed renewals as well as the byte minimum, without assuming equal
# capacities or allowing an unbounded test when renewal stops working.
while delivered < target_bytes or len(seen) < 3:
    assert time.monotonic() < deadline, 'two channel renewals did not complete within 180 seconds'
    size = min(512 * 1024, target_bytes - delivered) if delivered < target_bytes else 512 * 1024
    with urllib.request.urlopen(f'{sys.argv[1]}/down?bytes={size}', timeout=15) as response:
        body = response.read()
    assert len(body) == size, (len(body), size)
    delivered += size
    store, selected, _ = snapshot()
    usage = [record['session']['usage'] for record in store['sessions'].values()]
    billable = sum(item.get('billable_bytes', 0) for item in usage)
    observed = sum(item.get('rx_bytes', 0) + item.get('tx_bytes', 0) for item in usage)
    assert billable <= observed, f'billed {billable} bytes but observed only {observed}'
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
