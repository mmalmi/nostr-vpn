#!/usr/bin/env python3
"""Complete a real mint operation after the buyer switches from Manual to Direct."""
import json
import pathlib
import subprocess
import sys
import time
import urllib.request

phase, mint, final_mode, base_url, seller_ip = sys.argv[1:]
data = pathlib.Path('/root/.config/nvpn')
receipt = pathlib.Path('/tmp/nvpn-mode-funding-session')


def cli(*args):
    return subprocess.check_output(['nvpn', *args], text=True, timeout=40)


def store():
    return json.loads((data / 'paid-routes.json').read_text())


if phase == 'pending':
    cli('set', '--internet-source', 'direct')
    cli('set', '--internet-source', 'paid_manual')
    offer = next(iter(store()['offers']))
    purchased = json.loads(cli('paid-exit', 'buy', offer, '--mint', mint,
                               '--channel-capacity-sat', '3', '--json'))
    session_id = purchased['session']['session_id']
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        requests = data / 'cashu/daemon-ipc/requests'
        pending = []
        for path in requests.glob('*.json'):
            try:
                pending.append(json.loads(path.read_text()))
            except (FileNotFoundError, json.JSONDecodeError):
                continue
        if any(item['command'].get('request', {}).get('client_request_id') == session_id
               for item in pending):
            break
        time.sleep(0.1)
    else:
        raise AssertionError('Manual did not start a real wallet funding request')
    cli('set', '--internet-source', 'direct')
    assert json.loads(cli('status', '--json'))['internet_source'] == 'direct'
    receipt.write_text(session_id)
    print('Manual -> Direct while the real mint request is in flight', flush=True)
elif phase == 'completed':
    session_id = receipt.read_text()
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        current = store()
        payment = current['sessions'][session_id]['session']['payment'].get('cashu_spilman_payment')
        if payment and payment.get('funding_proofs') and payment.get('signature'):
            assert json.loads(cli('status', '--json'))['internet_source'] == 'direct'
            assert current['selected_buyer_session_id'] == session_id
            print('Late wallet result attached to its original session; Direct stayed selected', flush=True)
            break
        time.sleep(0.25)
    else:
        raise AssertionError('mode switch lost the completed wallet funding result')
    cli('set', '--internet-source', 'paid_' + final_mode)
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(base_url + '/source-ip', timeout=3) as response:
                assert json.load(response)['ip'] == seller_ip
            break
        except (OSError, AssertionError):
            time.sleep(1)
    else:
        raise AssertionError('paid route did not resume using the late funding result')
else:
    raise AssertionError(f'unknown phase: {phase}')
