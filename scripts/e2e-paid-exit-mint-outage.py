#!/usr/bin/env python3
"""Exercise a stalled mint and recovery in the isolated, funded Docker buyer."""
import json
import pathlib
import sys
import time
import urllib.request

directory = pathlib.Path('/root/.config/nvpn')
original_path = pathlib.Path('/tmp/nvpn-mint-outage-session')
phase, base_url, expected_ip = sys.argv[1:]


def snapshot():
    store = json.loads((directory / 'paid-routes.json').read_text())
    selected = store.get('selected_buyer_session_id', '')
    record = store.get('sessions', {}).get(selected)
    channel = store['channels'][record['session']['payment']['channel_id']] if record else {}
    return store, selected, record, channel


def assert_responsive():
    state = json.loads((directory / 'daemon.state.json').read_text())
    assert time.time() - state['updated_at'] < 12, 'wallet request blocked daemon updates'
    with urllib.request.urlopen(f'{base_url}/source-ip', timeout=3) as response:
        observed = json.load(response)['ip']
    assert observed == expected_ip, f'expected source {expected_ip}, observed {observed}'


deadline = time.monotonic() + 120
if phase == 'outage':
    original = None
    first_error_at = None
    while time.monotonic() < deadline:
        store, selected, record, channel = snapshot()
        if record and record.get('funding_started_unix', 0):
            if original is None:
                original = selected
                original_path.write_text(original)
            assert selected == original, 'mint outage discarded the selected session'
            assert len(store['sessions']) == 1, 'mint outage opened another trial'
            # Allow the route reconciliation tick to remove the trial route.
            if time.time() - record['funding_started_unix'] >= 3:
                assert_responsive()
            if channel.get('error'):
                if first_error_at is None:
                    first_error_at = channel['updated_at_unix']
                if channel['updated_at_unix'] >= first_error_at + 30:
                    print('Mint outage: daemon and Direct traffic stayed responsive; '
                          'same session retried beyond the provider timeout', flush=True)
                    break
        elif original is not None:
            raise AssertionError('pending funding disappeared while the mint was paused')
        time.sleep(1)
    else:
        raise AssertionError('stalled mint did not produce a bounded, durable funding retry')
elif phase == 'recovered':
    original = original_path.read_text()
    while time.monotonic() < deadline:
        store, selected, record, channel = snapshot()
        assert selected == original, 'mint recovery replaced the original session'
        assert len(store['sessions']) == 1, 'mint recovery created another channel session'
        if record and not record.get('funding_started_unix', 0):
            payment = record['session']['payment'].get('cashu_spilman_payment')
            lease = record['session']['lease_id']
            if payment and lease in store.get('buyer_session_admissions', {}):
                assert not channel.get('error'), 'funding error remained after recovery'
                # The admission has been persisted; wait for route installation.
                time.sleep(3)
                assert_responsive()
                print('Mint recovery: same session funded and admitted automatically; '
                      'traffic uses the seller again', flush=True)
                break
        time.sleep(1)
    else:
        raise AssertionError('payment and routing did not recover after the mint resumed')
else:
    raise AssertionError(f'unknown test phase: {phase}')
