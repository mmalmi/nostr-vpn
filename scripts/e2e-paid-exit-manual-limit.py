#!/usr/bin/env python3
"""Spend a Manual channel without renewal consent to its limit inside the Docker buyer.

The buyer must not open or fund a replacement channel, and its wallet must not
pay for one, after the channel has passed the renewal and handover thresholds.
"""
import http.client
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.request

store_path = pathlib.Path('/root/.config/nvpn/paid-routes.json')
probe_url, price, mint_url, label = sys.argv[1], int(sys.argv[2]), sys.argv[3], sys.argv[4]


def load_store():
    return json.loads(store_path.read_text())


def wallet_balance_sat():
    output = subprocess.check_output(
        ['nvpn', 'paid-exit', 'wallet', '--json', 'show', '--refresh'],
        env=dict(os.environ, RUST_LOG='warn'),
    )
    entries = json.loads(output).get('cashu', {}).get('entries', [])
    return sum(entry['balance'] for entry in entries
               if entry['mint_url'] == mint_url and entry['unit'] == 'sat')


def assert_no_replacement(store, context):
    new = set(store['sessions']) - sessions_before
    assert not new, f'{label}: {context}: opened replacement session(s) {sorted(new)}'
    renewals = store.get('buyer_session_renewals', {})
    assert selected not in renewals, f'{label}: {context}: prepared renewal {renewals[selected]}'


store = load_store()
selected = store['selected_buyer_session_id']
assert store.get('manual_renewal_session_id', '') != selected, \
    f'{label}: session unexpectedly carries renewal consent'
sessions_before = set(store['sessions'])
payment = store['sessions'][selected]['session']['payment']
capacity_msat = payment['capacity_sat'] * 1000
balance_before = wallet_balance_sat()

# Download until the buyer has paid the whole channel. That passes both the
# renewal and handover thresholds. The seller's cut-off trails the payments, so
# a failed request also ends the loop.
limit_msat = capacity_msat - 1000
delivered = 0
deadline = time.monotonic() + 180
while load_store()['sessions'][selected]['session']['payment']['paid_msat'] < limit_msat:
    assert time.monotonic() < deadline, \
        f'{label}: channel did not reach its limit within 180 seconds after {delivered} bytes'
    try:
        with urllib.request.urlopen(f'{probe_url}/down?bytes={512 * 1024}', timeout=5) as response:
            delivered += len(response.read())
    except (OSError, http.client.HTTPException):
        time.sleep(1)
    assert_no_replacement(load_store(), 'while spending')

# Renewal is evaluated on every Manual health update. Give it time to act on
# the passed thresholds, then confirm that it did not.
time.sleep(30)
store = load_store()
assert_no_replacement(store, 'after the limit')
payment = store['sessions'][selected]['session']['payment']
assert payment['paid_msat'] <= capacity_msat, f'{label}: paid beyond channel capacity'
balance_after = wallet_balance_sat()
assert balance_after >= balance_before, \
    f'{label}: wallet balance fell from {balance_before} to {balance_after} sat'
print(f'Manual {label}: channel reached its limit after {delivered} bytes; '
      f'no replacement opened and wallet stayed at {balance_after} sat', flush=True)
