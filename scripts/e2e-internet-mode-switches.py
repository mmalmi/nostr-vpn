#!/usr/bin/env python3
"""All 25 Internet mode transitions against isolated real Docker daemons."""
import ipaddress
import json
import pathlib
import subprocess
import sys
import time
import urllib.request

base_url, seller_ip, direct_ip, upstream_ip, private_peer, mint, final_mode = sys.argv[1:]
data = pathlib.Path('/root/.config/nvpn')
modes = ('paid_automatic', 'paid_manual', 'direct', 'private_vpn', 'wireguard')


def cli(*args):
    return subprocess.check_output(['nvpn', *args], text=True, timeout=40)


def snapshot():
    store = json.loads((data / 'paid-routes.json').read_text())
    session = store['sessions'].get(store.get('selected_buyer_session_id'))
    channel = store['channels'][session['session']['payment']['channel_id']] if session else None
    return store, session, channel


def fetch(path, payload=None):
    with urllib.request.urlopen(base_url + path, data=payload, timeout=4) as response:
        return response.read()


def ready(mode):
    expected_ip = {'direct': direct_ip, 'private_vpn': upstream_ip,
                   'wireguard': upstream_ip}.get(mode, seller_ip)
    deadline = time.monotonic() + 90
    last_error = None
    while time.monotonic() < deadline:
        try:
            status = json.loads(cli('status', '--json', '--discover-secs', '0'))
            assert status['internet_source'] == mode, status['internet_source']
            assert json.loads(fetch('/source-ip'))['ip'] == expected_ip, 'wrong egress'
            if mode.startswith('paid_'):
                _, session, channel = snapshot()
                assert session and channel['status'] not in ('closing', 'closed', 'failed')
                assert session['session']['payment'].get('cashu_spilman_payment'), 'not funded'
                assert session['session'].get('realized_exit_ip'), 'no fresh health check'
            answer = subprocess.check_output(
                ['dig', '+short', '+time=3', '+tries=1', 'example.com', 'A'],
                text=True, timeout=5).strip()
            assert answer and ipaddress.ip_address(answer.splitlines()[-1]).version == 4, 'DNS unavailable'
            assert len(fetch('/down?bytes=16384')) == 16384, 'download failed'
            assert fetch('/up', b'mode-switch' * 1024) == b'ok', 'upload failed'
            return snapshot()
        except (AssertionError, OSError, ValueError, subprocess.SubprocessError) as error:
            last_error = error
            time.sleep(1)
    raise AssertionError(f'{mode} failed to restore traffic/DNS: {last_error}')


def choose(mode):
    if mode == 'private_vpn':
        cli('set', '--internet-source', mode, '--exit-node', private_peer)
    elif mode == 'paid_manual':
        _, session, channel = snapshot()
        cli('set', '--internet-source', mode)
        # Reuse an open session, including Automatic's existing paid credit.
        if session and channel['status'] not in ('closing', 'closed', 'failed'):
            cli('paid-exit', 'use', session['session']['session_id'])
        else:
            # A deliberately settled channel cannot be spent a second time.
            store, _, _ = snapshot()
            offer = next(iter(store['offers']))
            cli('paid-exit', 'buy', offer, '--mint', mint, '--channel-capacity-sat', '20')
    else:
        cli('set', '--internet-source', mode)


# An Euler walk visits every directed edge, including each self-transition,
# once without resetting the fixture between pairs.
adjacency = {mode: list(modes) for mode in modes}
stack, walk = ['paid_automatic'], []
while stack:
    if adjacency[stack[-1]]:
        stack.append(adjacency[stack[-1]].pop())
    else:
        walk.append(stack.pop())
walk.reverse()
choose(walk[0])
ready(walk[0])
covered = set()
for previous, mode in zip(walk, walk[1:]):
    before, prior_session, prior_channel = snapshot()
    choose(mode)
    after, session, channel = ready(mode)
    if previous.startswith('paid_') and mode.startswith('paid_'):
        assert channel['channel_id'] == prior_channel['channel_id'], (
            f'{previous} -> {mode}: discarded usable paid credit')
        assert len(after['sessions']) == len(before['sessions']), 'unnecessary new session'
        assert session['session']['payment']['paid_msat'] >= prior_session['session']['payment']['paid_msat']
    covered.add((previous, mode))
    print(f'Internet modes: {previous} -> {mode}: DNS, upload, download, egress passed', flush=True)
assert covered == {(a, b) for a in modes for b in modes}
choose('paid_' + final_mode)
ready('paid_' + final_mode)
print('All 25 Internet mode transitions passed with real traffic and DNS', flush=True)
