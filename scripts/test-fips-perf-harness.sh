#!/usr/bin/env bash
# Local self-tests for the Docker nvpn+FIPS perf harness helpers.
#
# These tests do not start Docker. They pin the ping parser and threshold guard
# behavior so p95/p99 latency in phase summaries is also a real pass/fail signal.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PERF_SCRIPT="$ROOT_DIR/scripts/e2e-fips-perf-regression-docker.sh"

# shellcheck source=scripts/e2e-fips-perf-regression-docker.sh
source "$PERF_SCRIPT"

fail() {
  printf 'nvpn+FIPS perf harness self-test failed: %s\n' "$*" >&2
  exit 1
}

assert_eq() {
  local got="$1"
  local want="$2"
  local label="$3"
  [[ "$got" == "$want" ]] || fail "$label: got '$got', want '$want'"
}

assert_file_contains() {
  local file="$1"
  local pattern="$2"
  local label="$3"
  grep -Fq "$pattern" "$file" || fail "$label: missing '$pattern'"
}

assert_file_not_contains() {
  local file="$1"
  local pattern="$2"
  local label="$3"
  if grep -Fq "$pattern" "$file"; then
    fail "$label: unexpectedly contained '$pattern'"
  fi
}

assert_fails_with() {
  local label="$1"
  local pattern="$2"
  shift 2
  local err
  err="$(mktemp)"
  if "$@" 2>"$err"; then
    cat "$err" >&2
    rm -f "$err"
    fail "$label: command unexpectedly passed"
  fi
  if ! grep -Fq "$pattern" "$err"; then
    cat "$err" >&2
    rm -f "$err"
    fail "$label: expected stderr to contain '$pattern'"
  fi
  rm -f "$err"
}

fixture_ping_output() {
  cat <<'EOF'
PING 198.51.100.1 (198.51.100.1) 56(84) bytes of data.
64 bytes from 198.51.100.1: icmp_seq=1 ttl=64 time=1.0 ms
64 bytes from 198.51.100.1: icmp_seq=2 ttl=64 time=2.0 ms
64 bytes from 198.51.100.1: icmp_seq=3 ttl=64 time=3.0 ms
64 bytes from 198.51.100.1: icmp_seq=4 ttl=64 time=4.0 ms
64 bytes from 198.51.100.1: icmp_seq=5 ttl=64 time=5.0 ms
64 bytes from 198.51.100.1: icmp_seq=6 ttl=64 time=6.0 ms
64 bytes from 198.51.100.1: icmp_seq=7 ttl=64 time=7.0 ms
64 bytes from 198.51.100.1: icmp_seq=8 ttl=64 time=8.0 ms
64 bytes from 198.51.100.1: icmp_seq=9 ttl=64 time=9.0 ms
64 bytes from 198.51.100.1: icmp_seq=10 ttl=64 time=10.0 ms
64 bytes from 198.51.100.1: icmp_seq=11 ttl=64 time=11.0 ms
64 bytes from 198.51.100.1: icmp_seq=12 ttl=64 time=12.0 ms
64 bytes from 198.51.100.1: icmp_seq=13 ttl=64 time=13.0 ms
64 bytes from 198.51.100.1: icmp_seq=14 ttl=64 time=14.0 ms
64 bytes from 198.51.100.1: icmp_seq=15 ttl=64 time=15.0 ms
64 bytes from 198.51.100.1: icmp_seq=16 ttl=64 time=16.0 ms
64 bytes from 198.51.100.1: icmp_seq=17 ttl=64 time=17.0 ms
64 bytes from 198.51.100.1: icmp_seq=18 ttl=64 time=18.0 ms
64 bytes from 198.51.100.1: icmp_seq=19 ttl=64 time=19.0 ms
64 bytes from 198.51.100.1: icmp_seq=20 ttl=64 time=100.0 ms

--- 198.51.100.1 ping statistics ---
20 packets transmitted, 20 received, 0% packet loss, time 1900ms
rtt min/avg/max/mdev = 1.000/5.000/100.000/20.000 ms
EOF
}

fixture_iperf_output() {
  cat <<'EOF'
{
  "end": {
    "sum_received": {
      "bits_per_second": 123000000
    },
    "sum_sent": {
      "retransmits": 7
    }
  }
}
EOF
}

fixture_iperf_interval_output() {
  cat <<'EOF'
{
  "intervals": [
    {
      "streams": [
        {
          "snd_cwnd": 111,
          "rtt": 222,
          "rttvar": 33
        }
      ],
      "sum": {
        "start": 0,
        "end": 1,
        "bits_per_second": 123456789,
        "retransmits": 2,
        "omitted": true
      }
    },
    {
      "streams": [
        {
          "retransmits": 3,
          "snd_cwnd": 444,
          "rtt": 555,
          "rttvar": 66
        },
        {
          "retransmits": 4
        }
      ],
      "sum": {
        "start": 1,
        "end": 2,
        "bits_per_second": 987654321
      }
    },
    {
      "streams": [],
      "sum": {
        "start": 2,
        "end": 3,
        "bits_per_second": 0,
        "omitted": false
      }
    }
  ]
}
EOF
}

fixture_iperf_with_server_output() {
  cat <<'EOF'
{
  "intervals": [],
  "server_output_json": {
    "intervals": [
      {
        "streams": [
          {
            "snd_cwnd": 777,
            "rtt": 888,
            "rttvar": 99
          }
        ],
        "sum": {
          "start": 0,
          "end": 1,
          "bits_per_second": 234567890,
          "retransmits": 9,
          "omitted": false
        }
      }
    ],
    "end": {
      "sum_sent": {
        "retransmits": 9
      }
    }
  }
}
EOF
}

fixture_forward_iperf_with_server_output() {
  cat <<'EOF'
{
  "intervals": [
    {
      "streams": [
        {
          "snd_cwnd": 321,
          "rtt": 654,
          "rttvar": 87
        }
      ],
      "sum": {
        "start": 0,
        "end": 1,
        "bits_per_second": 345678901,
        "retransmits": 4,
        "omitted": false
      }
    }
  ],
  "end": {
    "sum_sent": {
      "retransmits": 4,
      "sender": true
    }
  },
  "server_output_json": {
    "intervals": [
      {
        "streams": [
          {
            "snd_cwnd": 999,
            "rtt": 999,
            "rttvar": 999
          }
        ],
        "sum": {
          "start": 0,
          "end": 1,
          "bits_per_second": 1,
          "retransmits": 99,
          "omitted": false
        }
      }
    ],
    "end": {
      "sum_sent": {
        "retransmits": 99,
        "sender": false
      }
    }
  }
}
EOF
}

test_ping_parser_percentiles() {
  local ping_output stats loss avg p95 p99 max
  ping_output="$(fixture_ping_output)"
  stats="$(printf '%s\n' "$ping_output" | parse_ping_stats)"
  read -r loss avg p95 p99 max <<<"$stats"

  assert_eq "$loss" "0" "packet loss"
  assert_eq "$avg" "5.000" "average latency"
  assert_eq "$p95" "19" "p95 latency"
  assert_eq "$p99" "100" "p99 latency"
  assert_eq "$max" "100.000" "max latency"
}

test_ping_thresholds() {
  local ping_output
  ping_output="$(fixture_ping_output)"

  assert_ping_ok "fixture pass" "$ping_output" 0 5 100 19 100 >/dev/null

  assert_fails_with \
    "p95 threshold" \
    "fixture p95 ping p95 ms" \
    bash -c 'source "$1"; assert_ping_ok "fixture p95" "$2" 0 5 200 18 200 >/dev/null' \
    bash "$PERF_SCRIPT" "$ping_output"

  assert_fails_with \
    "p99 threshold" \
    "fixture p99 ping p99 ms" \
    bash -c 'source "$1"; assert_ping_ok "fixture p99" "$2" 0 5 200 19 99 >/dev/null' \
    bash "$PERF_SCRIPT" "$ping_output"

  assert_fails_with \
    "default percentile threshold" \
    "fixture default ping p99 ms" \
    bash -c 'source "$1"; assert_ping_ok "fixture default" "$2" 0 5 99 >/dev/null' \
    bash "$PERF_SCRIPT" "$ping_output"
}

test_iperf_parser_and_tcp_thresholds() {
  local iperf_output got
  iperf_output="$(fixture_iperf_output)"

  got="$(printf '%s\n' "$iperf_output" | iperf_mbps)"
  assert_eq "$got" "123" "iperf Mbps"

  got="$(printf '%s\n' "$iperf_output" | iperf_retransmits)"
  assert_eq "$got" "7" "iperf retransmits"

  assert_float_at_least 101 100 "fixture TCP throughput Mbps"
  assert_int_at_most_if_set 7 "" "fixture TCP retransmits"
  assert_int_at_most_if_set 7 7 "fixture TCP retransmits"

  assert_fails_with \
    "TCP throughput floor" \
    "fixture TCP throughput Mbps" \
    bash -c 'source "$1"; assert_float_at_least 99 100 "fixture TCP throughput Mbps"' \
    bash "$PERF_SCRIPT"

  assert_fails_with \
    "TCP retransmit ceiling" \
    "fixture TCP retransmits" \
    bash -c 'source "$1"; assert_int_at_most_if_set 8 7 "fixture TCP retransmits"' \
    bash "$PERF_SCRIPT"
}

test_iperf_progress_guard() {
  local got good_json bad_json

  got="$(fixture_iperf_interval_output | iperf_stall_interval_count 1)"
  assert_eq "$got" "1" "iperf stalled interval count"

  good_json="$(fixture_forward_iperf_with_server_output)"
  bad_json="$(fixture_iperf_interval_output)"

  (
    MIN_IPERF_INTERVAL_MBIT=1
    MAX_IPERF_STALL_INTERVALS=0
    assert_iperf_progress_ok "fixture good" "$good_json"
  )

  assert_fails_with \
    "iperf interval stall guard" \
    "fixture bad had 1 iperf interval(s) below 1 Mbps" \
    bash -c 'source "$1"; MIN_IPERF_INTERVAL_MBIT=1; MAX_IPERF_STALL_INTERVALS=0; assert_iperf_progress_ok "fixture bad" "$2"' \
    bash "$PERF_SCRIPT" "$bad_json"
}

test_iperf_interval_summary() {
  local got expected

  got="$(fixture_iperf_interval_output | iperf_interval_summary)"
  expected=$'interval\tomitted\tstart_sec\tend_sec\tmbps\tretransmits\tsnd_cwnd_bytes\trtt_us\trttvar_us\n0\ttrue\t0\t1\t123.5\t2\t111\t222\t33\n1\tfalse\t1\t2\t987.7\t7\t444\t555\t66\n2\tfalse\t2\t3\t0\t\t\t\t'
  assert_eq "$got" "$expected" "iperf interval summary"

  got="$(fixture_iperf_with_server_output | iperf_server_json | iperf_interval_summary)"
  expected=$'interval\tomitted\tstart_sec\tend_sec\tmbps\tretransmits\tsnd_cwnd_bytes\trtt_us\trttvar_us\n0\tfalse\t0\t1\t234.6\t9\t777\t888\t99'
  assert_eq "$got" "$expected" "iperf server interval summary"

  if fixture_iperf_interval_output | iperf_server_json >/dev/null 2>&1; then
    fail "iperf server JSON extractor should ignore client-only JSON"
  fi
}

test_iperf_sender_summary() {
  local got expected

  got="$(fixture_forward_iperf_with_server_output | iperf_sender_json | iperf_interval_summary)"
  expected=$'interval\tomitted\tstart_sec\tend_sec\tmbps\tretransmits\tsnd_cwnd_bytes\trtt_us\trttvar_us\n0\tfalse\t0\t1\t345.7\t4\t321\t654\t87'
  assert_eq "$got" "$expected" "forward sender interval summary prefers client sender"

  got="$(fixture_iperf_with_server_output | iperf_sender_json | iperf_interval_summary)"
  expected=$'interval\tomitted\tstart_sec\tend_sec\tmbps\tretransmits\tsnd_cwnd_bytes\trtt_us\trttvar_us\n0\tfalse\t0\t1\t234.6\t9\t777\t888\t99'
  assert_eq "$got" "$expected" "reverse sender interval summary prefers server sender"

  got="$(fixture_iperf_interval_output | iperf_sender_interval_summary)"
  expected=$'intervals\tmbps_min\tmbps_max\tretransmits_total\tretransmits_max_interval\tsnd_cwnd_min_bytes\trtt_max_us\trttvar_max_us\n2\t0\t987.7\t7\t7\t444\t555\t66'
  assert_eq "$got" "$expected" "sender interval rollup"
}

test_iperf_timeout_configuration() {
  local got

  got="$(
    NVPN_PERF_DURATION_SECS=3 NVPN_PERF_LOAD_DURATION_SECS=12 \
      bash -c 'source "$1"; printf "%s" "$IPERF_TIMEOUT_SECS"' bash "$PERF_SCRIPT"
  )"
  assert_eq "$got" "42" "iperf timeout uses longer load duration"

  got="$(
    NVPN_PERF_DURATION_SECS=9 NVPN_PERF_LOAD_DURATION_SECS=4 \
      bash -c 'source "$1"; printf "%s" "$IPERF_TIMEOUT_SECS"' bash "$PERF_SCRIPT"
  )"
  assert_eq "$got" "39" "iperf timeout uses longer normal duration"

  got="$(
    NVPN_DOCKER_IPERF_TIMEOUT_SECS=17 \
      bash -c 'source "$1"; printf "%s" "$IPERF_TIMEOUT_SECS"' bash "$PERF_SCRIPT"
  )"
  assert_eq "$got" "17" "iperf timeout honors override"
}

test_iperf_probes_use_container_timeout() {
  local args_path timeout_count
  args_path="$(mktemp)"

  (
    BOB_TUNNEL_IP="198.51.100.1"
    DURATION=3
    LOAD_DURATION=4
    IPERF_TIMEOUT_SECS=11
    COMPOSE=(fixture_compose_timeout)

    fixture_compose_timeout() {
      printf '%s\n' "$*" >>"$args_path"
      case " $* " in
        *" ping "*) fixture_ping_output ;;
        *) fixture_iperf_output ;;
      esac
    }

    run_iperf_json "fixture forward" >/dev/null
    run_concurrent_probe "fixture-phase" "forward" 100 2 250 1000 1000 1000 >/dev/null
  )

  timeout_count="$(grep -Fc 'exec -T node-a timeout --kill-after=5s 11 iperf3' "$args_path")"
  assert_eq "$timeout_count" "2" "plain and load iperf probes use timeout"
  assert_file_contains "$args_path" " -t 3 " "plain iperf uses normal duration"
  assert_file_contains "$args_path" " -t 4 " "load iperf uses load duration"

  rm -f "$args_path"
}

test_concurrent_iperf_timeout_is_reported() {
  local err
  err="$(mktemp)"

  if (
    BOB_TUNNEL_IP="198.51.100.1"
    LOAD_DURATION=4
    IPERF_TIMEOUT_SECS=2
    COMPOSE=(fixture_compose_timeout_failure)

    fixture_compose_timeout_failure() {
      case " $* " in
        *" ping "*) fixture_ping_output ;;
        *" timeout "*) return 124 ;;
        *) fixture_iperf_output ;;
      esac
    }

    run_concurrent_probe "fixture-phase" "reverse" 100 2 250 1000 1000 1000 -R
  ) 2>"$err"; then
    cat "$err" >&2
    rm -f "$err"
    fail "concurrent iperf timeout unexpectedly passed"
  fi

  assert_file_contains "$err" "fixture-phase reverse iperf timed out after 2s" "concurrent iperf timeout message"
  rm -f "$err"
}

test_direct_underlay_policy() {
  (
    direct_underlay_bytes() { printf '42\n'; }
    assert_direct_counter_advanced node-a 40 "fixture node-a" >/dev/null
    assert_eq "$LAST_DIRECT_DELTA" "2" "direct underlay delta"
    assert_eq "$LAST_DIRECT_TOTAL" "42" "direct underlay total"
  )

  assert_fails_with \
    "direct underlay no-progress" \
    "fixture node-a did not use the configured direct UDP underlay path" \
    bash -c 'source "$1"; direct_underlay_bytes() { printf "40\n"; }; assert_direct_counter_advanced node-a 40 "fixture node-a"' \
    bash "$PERF_SCRIPT"
}

test_translated_nvpn_process_guard() {
  local native translated qemu
  native='30 /usr/local/bin/nvpn connect'
  translated='30 /run/rosetta/rosetta /usr/local/bin/nvpn /usr/local/bin/nvpn daemon --config /cfg/container.toml'
  qemu='30 /usr/bin/qemu-x86_64 /usr/local/bin/nvpn daemon --config /cfg/container.toml'

  if docker_bench_process_uses_translation "$native"; then
    fail "native nvpn process was classified as translated"
  fi
  if ! docker_bench_process_uses_translation "$translated"; then
    fail "Rosetta nvpn process was not classified as translated"
  fi
  if ! docker_bench_process_uses_translation "$qemu"; then
    fail "QEMU nvpn process was not classified as translated"
  fi
}

test_pipeline_summary_collects_fips_and_nvpn_lines() {
  local got

  got="$(
    latest_pipeline_lines_from_stdin <<'EOF'
[pipe 5s] endpoint_event_wait=1/s
[nvpn-pipe 5s] nvpn_tun_write=2/s
[pipe 5s] endpoint_event_wait=3/s
[nvpn-pipe 5s] nvpn_tun_to_mesh_queue_wait=4/s
EOF
  )"
  assert_eq \
    "$got" \
    "[pipe 5s] endpoint_event_wait=3/s | [nvpn-pipe 5s] nvpn_tun_to_mesh_queue_wait=4/s" \
    "combined pipeline summary"

  got="$(
    latest_pipeline_lines_from_stdin <<'EOF'
[pipe 5s] endpoint_event_wait=1/s
EOF
  )"
  assert_eq "$got" "[pipe 5s] endpoint_event_wait=1/s" "FIPS-only pipeline summary"

  got="$(
    latest_pipeline_lines_from_stdin <<'EOF'
[nvpn-pipe 5s] nvpn_tun_write=2/s
EOF
  )"
  assert_eq "$got" "[nvpn-pipe 5s] nvpn_tun_write=2/s" "nvpn-only pipeline summary"
}

test_pipeline_summary_prefers_peak_wait_lines() {
  local got

  got="$(
    latest_pipeline_lines_from_stdin <<'EOF'
[pipe 5s] endpoint_event_wait=100/s avg=20us transport_queue_wait=100/s avg=10us
[nvpn-pipe 5s] nvpn_tun_to_mesh_queue_wait=100/s avg=5us
[pipe 5s] endpoint_event_wait=100/s avg=450us transport_queue_wait=100/s avg=40us
[nvpn-pipe 5s] nvpn_tun_to_mesh_queue_wait=100/s avg=60us
[pipe 5s] endpoint_event_wait=100/s avg=40us decrypt_fallback_wait=100/s avg=900us
[pipe 5s] endpoint_bulk_command_wait=100/s avg=1.4ms decrypt_fallback_wait=100/s avg=900us
[pipe 5s] endpoint_event_wait=1/s avg=4us transport_queue_wait=1/s avg=5us
[nvpn-pipe 5s] nvpn_tun_to_mesh_queue_wait=1/s avg=3us
EOF
  )"
  assert_eq \
    "$got" \
    "[pipe 5s] endpoint_bulk_command_wait=100/s avg=1.4ms decrypt_fallback_wait=100/s avg=900us | [nvpn-pipe 5s] nvpn_tun_to_mesh_queue_wait=100/s avg=60us" \
    "peak wait pipeline summary"
}

test_pipeline_summary_prefers_load_bearing_lines() {
  local got

  got="$(
    load_pipeline_lines_from_stdin <<'EOF'
[pipe 5s] fmp_worker_batch_packets=48000/s udp_send_connected=48000/s fmp_worker_queue_wait=48000/s avg=40us
[nvpn-pipe 5s] nvpn_tun_read=47000/s nvpn_tun_to_mesh_queue_wait=47000/s avg=20us
[pipe 5s] fmp_worker_batch_packets=12/s udp_send_connected=12/s fmp_worker_queue_wait=12/s avg=2.1ms
[nvpn-pipe 5s] nvpn_tun_read=9/s nvpn_tun_to_mesh_queue_wait=9/s avg=3.0ms
EOF
  )"
  assert_eq \
    "$got" \
    "[pipe 5s] fmp_worker_batch_packets=48000/s udp_send_connected=48000/s fmp_worker_queue_wait=48000/s avg=40us | [nvpn-pipe 5s] nvpn_tun_read=47000/s nvpn_tun_to_mesh_queue_wait=47000/s avg=20us" \
    "load-bearing pipeline summary"

  got="$(
    load_pipeline_lines_from_stdin <<'EOF'
[pipe 5s] fmp_worker_batch_packets=100/s endpoint_send=200/s
[pipe 5s] fmp_worker_batch_packets=100/s endpoint_send=200/s udp_send_connected=200/s
EOF
  )"
  assert_eq \
    "$got" \
    "[pipe 5s] fmp_worker_batch_packets=100/s endpoint_send=200/s udp_send_connected=200/s" \
    "load-bearing pipeline summary keeps latest tie"
}

test_pipeline_summary_scopes_selected_lines_after_start() {
  local got

  got="$(
    pipeline_lines_after_start_from_stdin 2 <<'EOF' | load_pipeline_lines_from_stdin
[pipe 5s] fmp_worker_batch_packets=355000/s udp_send_connected=355000/s fmp_worker_queue_wait=355000/s avg=1.0ms
[nvpn-pipe 5s] nvpn_tun_read=355000/s nvpn_tun_to_mesh_queue_wait=355000/s avg=1.0ms
[pipe 5s] fmp_worker_batch_packets=4200/s udp_send_connected=4200/s fmp_worker_queue_wait=4200/s avg=30us
[nvpn-pipe 5s] nvpn_tun_read=3900/s nvpn_tun_to_mesh_queue_wait=3900/s avg=20us
[pipe 5s] fmp_worker_batch_packets=12/s udp_send_connected=12/s fmp_worker_queue_wait=12/s avg=2.1ms
[nvpn-pipe 5s] nvpn_tun_read=9/s nvpn_tun_to_mesh_queue_wait=9/s avg=3.0ms
EOF
  )"
  assert_eq \
    "$got" \
    "[pipe 5s] fmp_worker_batch_packets=4200/s udp_send_connected=4200/s fmp_worker_queue_wait=4200/s avg=30us | [nvpn-pipe 5s] nvpn_tun_read=3900/s nvpn_tun_to_mesh_queue_wait=3900/s avg=20us" \
    "phase-scoped load-bearing pipeline summary"

  got="$(
    pipeline_lines_after_start_from_stdin 2 <<'EOF' | peak_wait_pipeline_lines_from_stdin
[pipe 5s] fmp_worker_batch_packets=355000/s fmp_worker_queue_wait=355000/s avg=1.0ms
[nvpn-pipe 5s] nvpn_tun_read=355000/s nvpn_tun_to_mesh_queue_wait=355000/s avg=1.0ms
[pipe 5s] fmp_worker_batch_packets=4200/s fmp_worker_queue_wait=4200/s avg=30us
[nvpn-pipe 5s] nvpn_tun_read=3900/s nvpn_tun_to_mesh_queue_wait=3900/s avg=20us
[pipe 5s] fmp_worker_batch_packets=12/s fmp_worker_queue_wait=12/s avg=2.1ms
[nvpn-pipe 5s] nvpn_tun_read=9/s nvpn_tun_to_mesh_queue_wait=9/s avg=3.0ms
EOF
  )"
  assert_eq \
    "$got" \
    "[pipe 5s] fmp_worker_batch_packets=12/s fmp_worker_queue_wait=12/s avg=2.1ms | [nvpn-pipe 5s] nvpn_tun_read=9/s nvpn_tun_to_mesh_queue_wait=9/s avg=3.0ms" \
    "phase-scoped peak-wait pipeline summary"
}

test_docker_pipeline_range_helpers() {
  local got

  got="$(
    docker_bench_pipeline_lines_in_range_from_stdin 1 3 <<'EOF'
[pipe 1s] before=1/s
[pipe 2s] selected=2/s
[pipe 3s] selected=3/s
[pipe 4s] after=4/s
EOF
  )"
  assert_eq \
    "$got" \
    $'[pipe 2s] selected=2/s\n[pipe 3s] selected=3/s' \
    "docker phase range pipeline lines"

  got="$(
    docker_bench_pipeline_hard_event_summary_from_stdin 2 4 <<'EOF'
[pipe 1s] encrypt_worker_queue_full=1/s total=10
[pipe 2s] encrypt_worker_queue_full=2/s total=12
[pipe 3s] encrypt_worker_queue_full=5/s total=15 connected_udp_kernel_dropped=6/s total=6 connected_udp_direct_decrypt_bulk_shed=4/s total=4
[pipe 4s] encrypt_worker_queue_full=3/s total=17
[pipe 5s] encrypt_worker_queue_full=7/s total=30
EOF
  )"
  assert_eq \
    "$got" \
    "connected_udp_kernel_dropped:max_rate_per_sec=6,total=6;connected_udp_direct_decrypt_bulk_shed:max_rate_per_sec=4,total=4;encrypt_worker_queue_full:max_rate_per_sec=5,total=5" \
    "docker phase range hard events ignore post-phase totals"
}

test_pipeline_queue_wait_top_summary() {
  local got

  got="$(pipeline_queue_wait_top_summary '[pipe 5s] endpoint_event_wait=10/s avg=40.0us p50<=32.8us p95<=262.1us p99<=524.3us max<=1.0ms allmax=5.7ms decrypt_fallback_bulk_wait=10/s avg=1.1ms p50<=2.1ms p95<=2.1ms p99<=8.4ms max<=16.8ms allmax=11.1ms | [nvpn-pipe 5s] nvpn_tun_to_mesh_queue_wait=10/s avg=31.0us p50<=32.8us p95<=131.1us p99<=524.3us max<=1.0ms allmax=2.5ms')"
  assert_eq \
    "$got" \
    "decrypt_fallback_bulk_wait:rate_per_sec=10,p95_ms=2.1,p99_ms=8.4,max_ms=16.8,allmax_ms=11.1" \
    "pipeline top queue wait summary"

  got="$(pipeline_queue_wait_top_summary '[nvpn-pipe 5s] nvpn_tun_to_mesh_queue_wait=10/s avg=31.0us p50<=32.8us p95<=131.1us p99<=524.3us max<=1.0ms allmax=2.5ms')"
  assert_eq \
    "$got" \
    "nvpn_tun_to_mesh_queue_wait:rate_per_sec=10,p95_ms=0.1311,p99_ms=0.5243,max_ms=1,allmax_ms=2.5" \
    "nvpn-only top queue wait summary"

  got="$(pipeline_queue_wait_top_summary '[pipe 5s] endpoint_command_wait=10/s avg=40.0us p50<=32.8us p95<=262.1us p99<=524.3us max<=1.0ms allmax=5.7ms endpoint_priority_command_wait=10/s avg=1.1ms p50<=2.1ms p95<=2.1ms p99<=4.2ms max<=4.2ms allmax=4.1ms')"
  assert_eq \
    "$got" \
    "endpoint_priority_command_wait:rate_per_sec=10,p95_ms=2.1,p99_ms=4.2,max_ms=4.2,allmax_ms=4.1" \
    "endpoint command lane top queue wait summary"

  got="$(pipeline_queue_wait_top_summary '[pipe 5s] endpoint_command_wait=244851/s avg=48.2us p50<=4.1us p95<=262.1us p99<=2.1ms max<=4.2ms allmax=9.9ms endpoint_priority_command_wait=1/s avg=14.5us p50<=16.4us p95<=65.5us p99<=65.5us max<=65.5us allmax=2.1ms endpoint_bulk_command_wait=244849/s avg=48.2us p50<=4.1us p95<=262.1us p99<=2.1ms max<=4.2ms allmax=3.4ms')"
  assert_eq \
    "$got" \
    "endpoint_bulk_command_wait:rate_per_sec=244849,p95_ms=0.2621,p99_ms=2.1,max_ms=4.2,allmax_ms=3.4" \
    "pipeline top queue wait prefers lane split on aggregate tie"

  got="$(pipeline_queue_wait_top_summary '[pipe 5s] decrypt_authenticated_session_bulk_wait=1/s avg=3.0ms p50<=2.1ms p95<=4.2ms p99<=8.4ms max<=16.8ms allmax=16.8ms decrypt_fsp_worker_priority_queue_wait=0.2/s avg=10.0ms p50<=8.4ms p95<=16.8ms p99<=33.6ms max<=67.1ms allmax=67.1ms')"
  assert_eq \
    "$got" \
    "decrypt_fsp_worker_priority_queue_wait:rate_per_sec=0.2,p95_ms=16.8,p99_ms=33.6,max_ms=67.1,allmax_ms=67.1" \
    "pipeline top queue wait includes authenticated/FSP worker waits"

  got="$(pipeline_queue_wait_top_summary '[pipe 5s] decrypt_authenticated_session_bulk_wait=10/s avg=1.0ms p50<=1.0ms p95<=2.1ms p99<=4.2ms max<=8.4ms allmax=8.4ms decrypt_direct_session_commit_wait=10/s avg=2.0ms p50<=2.1ms p95<=4.2ms p99<=16.8ms max<=33.6ms allmax=33.6ms')"
  assert_eq \
    "$got" \
    "decrypt_direct_session_commit_wait:rate_per_sec=10,p95_ms=4.2,p99_ms=16.8,max_ms=33.6,allmax_ms=33.6" \
    "pipeline top queue wait includes direct session waits"

  got="$(pipeline_queue_wait_top_summary '[pipe 5s] fmp_worker_bulk_queue_wait=10/s avg=1.0ms p50<=1.0ms p95<=2.1ms p99<=4.2ms max<=8.4ms allmax=8.4ms fmp_linux_bulk_container_ready_wait=10/s avg=2.0ms p50<=2.1ms p95<=4.2ms p99<=16.8ms max<=33.6ms allmax=33.6ms')"
  assert_eq \
    "$got" \
    "fmp_linux_bulk_container_ready_wait:rate_per_sec=10,p95_ms=4.2,p99_ms=16.8,max_ms=33.6,allmax_ms=33.6" \
    "pipeline top queue wait includes Linux bulk container waits"

  got="$(pipeline_queue_wait_top_summary '[pipe 5s] fsp_aead_worker_open_completion_wait=5/s avg=7.0ms p50<=8.4ms p95<=16.8ms p99<=33.6ms max<=67.1ms allmax=67.1ms')"
  assert_eq \
    "$got" \
    "fsp_aead_worker_open_completion_wait:rate_per_sec=5,p95_ms=16.8,p99_ms=33.6,max_ms=67.1,allmax_ms=67.1" \
    "pipeline top queue wait includes FSP worker-open waits"

  got="$(pipeline_queue_wait_top_summary '[pipe 5s] transport_priority_queue_wait=0.2/s avg=14.5us p50<=16.4us p95<=65.5us p99<=65.5us max<=65.5us allmax=2.1ms')"
  assert_eq \
    "$got" \
    "transport_priority_queue_wait:rate_per_sec=0.2,p95_ms=0.0655,p99_ms=0.0655,max_ms=0.0655,allmax_ms=2.1" \
    "pipeline top queue wait keeps fractional low-rate samples"

  got="$(pipeline_queue_wait_top_summary '[pipe 5s] udp_send_connected=10/s')"
  assert_eq "$got" "" "empty top queue wait summary"
}

test_pipeline_fmp_worker_batch_summary() {
  local got

  got="$(pipeline_fmp_worker_batch_summary '[pipe 5s] fmp_worker_batch_flush=10/s fmp_worker_batch_packets=420/s fmp_worker_batch_full=9/s fmp_worker_batch_single=0.5/s endpoint_event_wait=10/s avg=40.0us | [nvpn-pipe 5s] nvpn_tun_write=2/s')"
  assert_eq \
    "$got" \
    "avg_packets=42.0,full_pct=90.0,single_pct=5.0,flush_per_sec=10,packets_per_sec=420" \
    "legacy FMP worker batch summary"

  got="$(pipeline_fmp_worker_batch_summary '[pipe 5s] fmp_worker_batch_flush=10/s fmp_worker_batch_packets=420/s fmp_worker_batch_priority_packets=105/s fmp_worker_batch_bulk_packets=315/s fmp_worker_batch_full=9/s fmp_worker_batch_single=0.5/s endpoint_event_wait=10/s avg=40.0us | [nvpn-pipe 5s] nvpn_tun_write=2/s')"
  assert_eq \
    "$got" \
    "avg_packets=42.0,full_pct=90.0,single_pct=5.0,priority_pct=25.0,bulk_pct=75.0,flush_per_sec=10,packets_per_sec=420,priority_packets_per_sec=105,bulk_packets_per_sec=315" \
    "lane-aware FMP worker batch summary"

  got="$(pipeline_fmp_worker_batch_summary '[pipe 5s] fmp_worker_batch_flush=10/s fmp_worker_batch_packets=420/s fmp_worker_batch_priority_packets=105/s fmp_worker_batch_bulk_packets=315/s fmp_worker_batch_full=9/s fmp_worker_batch_single=0.5/s fmp_send_group=12/s fmp_send_group_packets=420/s fmp_send_group_single=3/s fmp_send_group_split_target=1/s fmp_send_group_split_lane=2/s fmp_send_group_split_backpressure=0.5/s fmp_send_group_split_packet_cap=3/s endpoint_committed_bulk_dispatch_batch=4/s endpoint_committed_bulk_dispatch_packets=512/s endpoint_committed_bulk_dispatch_merged_batch=1.5/s endpoint_committed_bulk_dispatch_merged_packets=192/s endpoint_event_wait=10/s avg=40.0us | [nvpn-pipe 5s] nvpn_tun_write=2/s')"
  assert_eq \
    "$got" \
    "avg_packets=42.0,full_pct=90.0,single_pct=5.0,priority_pct=25.0,bulk_pct=75.0,flush_per_sec=10,packets_per_sec=420,priority_packets_per_sec=105,bulk_packets_per_sec=315,send_groups_per_flush=1.2,send_group_avg_packets=35.0,send_group_single_pct=25.0,send_groups_per_sec=12,send_group_packets_per_sec=420,send_group_split_total_per_sec=6.5,send_group_split_target_per_sec=1,send_group_split_lane_per_sec=2,send_group_split_backpressure_per_sec=0.5,send_group_split_packet_cap_per_sec=3,committed_bulk_dispatch_avg_packets=128.0,committed_bulk_dispatch_per_sec=4,committed_bulk_dispatch_packets_per_sec=512,committed_bulk_merged_batches_per_sec=1.5,committed_bulk_merged_packets_per_sec=192" \
    "FMP worker batch summary includes send group shape, split causes, and committed bulk coalescing"

  got="$(pipeline_fmp_worker_batch_summary '[pipe 5s] endpoint_event_wait=10/s avg=40.0us')"
  assert_eq "$got" "" "empty FMP worker batch summary"
}

test_pipeline_fmp_worker_dispatch_spread_summary() {
  local got

  got="$(pipeline_fmp_worker_dispatch_spread_summary '[pipe 5s] fmp_worker_dispatch_flow_keyed=99/s fmp_worker_dispatch_target_only=1/s fmp_worker_dispatch_worker0=25/s fmp_worker_dispatch_worker1=0/s fmp_worker_dispatch_worker2=0/s fmp_worker_dispatch_worker3=75/s fmp_worker_dispatch_worker_other=0/s endpoint_event_wait=10/s avg=40.0us')"
  assert_eq \
    "$got" \
    "active_workers=2,workers_ge1pct=2,top_worker=w3,top_pct=75.0,flow_keyed_pct=99.0,target_only_pct=1.0,total_per_sec=100,worker_rates=w0:25;w3:75" \
    "FMP worker dispatch spread summary"

  got="$(pipeline_fmp_worker_dispatch_spread_summary '[pipe 5s] endpoint_event_wait=10/s avg=40.0us')"
  assert_eq "$got" "" "empty FMP worker dispatch spread summary"
}

test_pipeline_fsp_owner_placement_summary() {
  local got

  got="$(pipeline_fsp_owner_placement_summary '[pipe 5s] decrypt_fsp_owner_same=500000/s decrypt_fsp_path_local=499990/s decrypt_fsp_path_local_bulk=499990/s endpoint_event_wait=10/s avg=40.0us')"
  assert_eq \
    "$got" \
    "owner=same,path=local,bulk_path=local,priority_path=unknown,owner_same_per_sec=500000,owner_mismatch_per_sec=0,path_local_per_sec=499990,path_handoff_per_sec=0,path_helper_per_sec=0,path_worker_open_per_sec=0,path_worker_open_striped_per_sec=0,path_local_priority_per_sec=0,path_local_bulk_per_sec=499990,path_handoff_priority_per_sec=0,path_handoff_bulk_per_sec=0,path_helper_bulk_per_sec=0,path_worker_open_bulk_per_sec=0,bulk_packets_per_sec=0,select_bulk_packets_per_sec=0,drain_bulk_packets_per_sec=0" \
    "FSP same-owner local placement summary"
  assert_eq \
    "$(pipeline_fsp_owner_placement_kind '[pipe 5s] decrypt_fsp_owner_same=500000/s decrypt_fsp_path_local=499990/s')" \
    "local" \
    "FSP same-owner local placement kind"

  got="$(pipeline_fsp_owner_placement_summary '[pipe 5s] decrypt_fsp_owner_mismatch=589000/s decrypt_fsp_path_handoff=589000/s decrypt_fsp_path_handoff_bulk=589000/s')"
  assert_eq \
    "$got" \
    "owner=mismatch,path=handoff,bulk_path=handoff,priority_path=unknown,owner_same_per_sec=0,owner_mismatch_per_sec=589000,path_local_per_sec=0,path_handoff_per_sec=589000,path_helper_per_sec=0,path_worker_open_per_sec=0,path_worker_open_striped_per_sec=0,path_local_priority_per_sec=0,path_local_bulk_per_sec=0,path_handoff_priority_per_sec=0,path_handoff_bulk_per_sec=589000,path_helper_bulk_per_sec=0,path_worker_open_bulk_per_sec=0,bulk_packets_per_sec=0,select_bulk_packets_per_sec=0,drain_bulk_packets_per_sec=0" \
    "FSP mismatch handoff placement summary"
  assert_eq \
    "$(pipeline_fsp_owner_placement_kind '[pipe 5s] decrypt_fsp_owner_mismatch=589000/s decrypt_fsp_path_handoff=589000/s')" \
    "handoff" \
    "FSP mismatch handoff placement kind"

  got="$(pipeline_fsp_owner_placement_summary '[pipe 5s] decrypt_fsp_owner_same=520000/s decrypt_fsp_path_worker_open=519900/s decrypt_fsp_path_worker_open_bulk=519900/s decrypt_fsp_path_local=100/s decrypt_fsp_path_local_priority=100/s')"
  assert_eq \
    "$got" \
    "owner=same,path=worker-open,bulk_path=worker-open,priority_path=local,owner_same_per_sec=520000,owner_mismatch_per_sec=0,path_local_per_sec=100,path_handoff_per_sec=0,path_helper_per_sec=0,path_worker_open_per_sec=519900,path_worker_open_striped_per_sec=0,path_local_priority_per_sec=100,path_local_bulk_per_sec=0,path_handoff_priority_per_sec=0,path_handoff_bulk_per_sec=0,path_helper_bulk_per_sec=0,path_worker_open_bulk_per_sec=519900,bulk_packets_per_sec=0,select_bulk_packets_per_sec=0,drain_bulk_packets_per_sec=0" \
    "FSP worker-open placement summary"
  assert_eq \
    "$(pipeline_fsp_owner_placement_kind '[pipe 5s] decrypt_fsp_owner_same=520000/s decrypt_fsp_path_worker_open=519900/s decrypt_fsp_path_local=100/s')" \
    "worker-open" \
    "FSP worker-open placement kind"

  got="$(pipeline_fsp_owner_placement_summary '[pipe 5s] decrypt_fsp_owner_mismatch=520000/s decrypt_fsp_path_worker_open=519900/s decrypt_fsp_path_worker_open_bulk=519900/s decrypt_fsp_path_worker_open_striped=519900/s decrypt_fsp_path_local=100/s decrypt_fsp_path_local_priority=100/s')"
  assert_eq \
    "$got" \
    "owner=mismatch,path=worker-open,bulk_path=worker-open,priority_path=local,owner_same_per_sec=0,owner_mismatch_per_sec=520000,path_local_per_sec=100,path_handoff_per_sec=0,path_helper_per_sec=0,path_worker_open_per_sec=519900,path_worker_open_striped_per_sec=519900,path_local_priority_per_sec=100,path_local_bulk_per_sec=0,path_handoff_priority_per_sec=0,path_handoff_bulk_per_sec=0,path_helper_bulk_per_sec=0,path_worker_open_bulk_per_sec=519900,bulk_packets_per_sec=0,select_bulk_packets_per_sec=0,drain_bulk_packets_per_sec=0" \
    "FSP striped worker-open placement summary"
}

test_pipeline_decrypt_worker_batch_summary() {
  local got

  got="$(pipeline_decrypt_worker_batch_summary '[pipe 5s] decrypt_worker_batch_flush=20/s decrypt_worker_batch_packets=640/s decrypt_worker_batch_priority_packets=64/s decrypt_worker_batch_bulk_packets=576/s decrypt_worker_batch_full=5/s decrypt_worker_batch_single=2/s fmp_send_group=12/s fmp_send_group_packets=420/s decrypt_worker_bulk_queue_wait=100/s avg=40.0us | [nvpn-pipe 5s] nvpn_tun_write=2/s')"
  assert_eq \
    "$got" \
    "avg_packets=32.0,full_pct=25.0,single_pct=10.0,priority_pct=10.0,bulk_pct=90.0,flush_per_sec=20,packets_per_sec=640,priority_packets_per_sec=64,bulk_packets_per_sec=576" \
    "lane-aware decrypt worker batch summary"

  got="$(pipeline_decrypt_worker_batch_summary '[pipe 5s] decrypt_worker_bulk_queue_wait=10/s avg=40.0us')"
  assert_eq "$got" "" "empty decrypt worker batch summary"
}

test_pipeline_decrypt_worker_spread_summary() {
  local got

  got="$(pipeline_decrypt_worker_spread_summary '[pipe 5s] decrypt_worker_batch_worker0=320/s decrypt_worker_batch_worker1=0/s decrypt_worker_batch_worker2=160/s decrypt_worker_batch_worker7=160/s decrypt_worker_batch_worker_other=0/s endpoint_event_wait=10/s avg=40.0us')"
  assert_eq \
    "$got" \
    "active_workers=3,workers_ge1pct=3,top_worker=w0,top_pct=50.0,total_packets_per_sec=640,worker_packet_rates=w0:320;w2:160;w7:160" \
    "decrypt worker packet spread summary"

  got="$(pipeline_decrypt_worker_spread_summary '[pipe 5s] decrypt_worker_bulk_queue_wait=10/s avg=40.0us')"
  assert_eq "$got" "" "empty decrypt worker packet spread summary"
}

test_pipeline_decrypt_worker_turn_mix_summary() {
  local got

  got="$(pipeline_decrypt_worker_turn_mix_summary '[pipe 5s] decrypt_worker_select_fmp_completion=2/s decrypt_worker_select_fsp_completion_batch=3/s decrypt_worker_select_fsp_completion_packets=96/s decrypt_worker_select_bulk_packets=480/s decrypt_worker_drain_aead_completion_batch=4/s decrypt_worker_drain_aead_completion_packets=128/s decrypt_worker_drain_bulk_packets=320/s decrypt_worker_bulk_interleave_aead_completion_batch=5/s decrypt_worker_bulk_interleave_aead_completion_packets=160/s decrypt_worker_bulk_interleave_budget_exhausted=0.2/s endpoint_event_wait=10/s avg=40.0us')"
  assert_eq \
    "$got" \
    "completion_packet_pct=32.4,completion_batches_per_sec=14,known_completion_packets_per_sec=384,bulk_packets_per_sec=800,select_fmp_completion_batches_per_sec=2,select_fsp_completion_batches_per_sec=3,select_fsp_completion_packets_per_sec=96,select_bulk_packets_per_sec=480,drain_completion_batches_per_sec=4,drain_completion_packets_per_sec=128,drain_bulk_packets_per_sec=320,interleave_completion_batches_per_sec=5,interleave_completion_packets_per_sec=160,interleave_budget_exhausted_per_sec=0.2" \
    "decrypt worker turn mix summary"

  got="$(pipeline_decrypt_worker_turn_mix_summary '[pipe 5s] decrypt_worker_bulk_queue_wait=10/s avg=40.0us')"
  assert_eq "$got" "" "empty decrypt worker turn mix summary"
}

test_pipeline_linux_bulk_container_summary() {
  local got

  got="$(pipeline_linux_bulk_container_summary '[pipe 5s] fmp_linux_bulk_container_enqueued=12/s total=60 fmp_linux_bulk_container_packets=960/s total=4800 fmp_linux_bulk_container_sent=10/s total=50 fmp_linux_bulk_container_sent_packets=800/s total=4000 fmp_linux_bulk_container_queue_wait=12/s avg=160.0us p50<=131.1us p95<=524.3us p99<=1.0ms max<=2.1ms allmax=3.4ms fmp_linux_bulk_container_ready_wait=12/s avg=150.0us p50<=131.1us p95<=262.1us p99<=524.3us max<=1.0ms allmax=1.9ms fmp_linux_bulk_container_first_slot_wait=12/s avg=42.0us p50<=32.8us p95<=131.1us p99<=262.1us max<=1.0ms allmax=1.2ms fmp_linux_bulk_container_all_slots_wait=12/s avg=267.0us p50<=524.3us p95<=524.3us p99<=1.0ms max<=2.1ms allmax=1.9ms')"
  assert_eq \
    "$got" \
    "avg_packets=80.0,avg_sent_packets=80.0,enqueued_per_sec=12,packets_per_sec=960,sent_per_sec=10,sent_packets_per_sec=800,queue_p95_ms=0.5243,queue_p99_ms=1,ready_p95_ms=0.2621,ready_p99_ms=0.5243,first_slot_p95_ms=0.1311,first_slot_p99_ms=0.2621,all_slots_p95_ms=0.5243,all_slots_p99_ms=1" \
    "Linux bulk container summary includes rates and wait stages"

  got="$(docker_bench_pipeline_linux_bulk_container_summary <<'EOF'
[pipe 5s] fmp_linux_bulk_container_enqueued=2/s fmp_linux_bulk_container_packets=40/s fmp_linux_bulk_container_sent=2/s fmp_linux_bulk_container_sent_packets=40/s
[pipe 5s] fmp_linux_bulk_container_enqueued=4/s fmp_linux_bulk_container_packets=400/s fmp_linux_bulk_container_sent=4/s fmp_linux_bulk_container_sent_packets=400/s fmp_linux_bulk_container_all_slots_wait=4/s avg=200.0us p50<=262.1us p95<=524.3us p99<=1.0ms max<=2.1ms allmax=1.9ms
EOF
)"
  assert_eq \
    "$got" \
    "avg_packets=100.0,avg_sent_packets=100.0,enqueued_per_sec=4,packets_per_sec=400,sent_per_sec=4,sent_packets_per_sec=400,all_slots_p95_ms=0.5243,all_slots_p99_ms=1" \
    "Linux bulk container summary picks busiest interval from stdin"

  got="$(pipeline_linux_bulk_container_summary '[pipe 5s] fmp_worker_batch_flush=10/s')"
  assert_eq "$got" "" "empty Linux bulk container summary"
}

test_pipeline_udp_send_batch_summary() {
  local got

  got="$(pipeline_udp_send_batch_summary '[pipe 5s] udp_send_gso_batch=10/s udp_send_gso_packets=420/s udp_send_gso_batch_ge32=7/s udp_send_gso_batch_ge48=3/s udp_send_gso_batch_eq64=1/s udp_send_sendmmsg_batch=2/s udp_send_sendmmsg_packets=4/s udp_send_sendmmsg_batch_ge32=1/s udp_send_sendmmsg_batch_ge48=0/s udp_send_sendmmsg_batch_eq64=0/s endpoint_event_wait=10/s avg=40.0us | [nvpn-pipe 5s] nvpn_tun_write=2/s')"
  assert_eq \
    "$got" \
    "gso_packet_pct=99.1,sendmmsg_packet_pct=0.9,avg_packets=35.3,gso_avg_packets=42.0,sendmmsg_avg_packets=2.0,gso_ge32_pct=70.0,gso_ge48_pct=30.0,gso_eq64_pct=10.0,sendmmsg_ge32_pct=50.0,sendmmsg_ge48_pct=0.0,sendmmsg_eq64_pct=0.0,gso_batch_per_sec=10,gso_packets_per_sec=420,sendmmsg_batch_per_sec=2,sendmmsg_packets_per_sec=4,total_packets_per_sec=424" \
    "GSO-heavy UDP send batch summary"

  got="$(pipeline_udp_send_batch_summary '[pipe 5s] udp_send_gso_batch=0/s udp_send_gso_packets=0/s udp_send_sendmmsg_batch=12.5/s udp_send_sendmmsg_packets=25/s endpoint_event_wait=10/s avg=40.0us')"
  assert_eq \
    "$got" \
    "gso_packet_pct=0.0,sendmmsg_packet_pct=100.0,avg_packets=2.0,gso_avg_packets=0.0,sendmmsg_avg_packets=2.0,gso_ge32_pct=0.0,gso_ge48_pct=0.0,gso_eq64_pct=0.0,sendmmsg_ge32_pct=0.0,sendmmsg_ge48_pct=0.0,sendmmsg_eq64_pct=0.0,gso_batch_per_sec=0,gso_packets_per_sec=0,sendmmsg_batch_per_sec=12.5,sendmmsg_packets_per_sec=25,total_packets_per_sec=25" \
    "sendmmsg-only UDP send batch summary stays compatible with old counters"

  got="$(pipeline_udp_send_batch_summary '[pipe 5s] endpoint_event_wait=10/s avg=40.0us')"
  assert_eq "$got" "" "empty UDP send batch summary"
}

test_pipeline_hard_event_summary() {
  local got

  got="$(
    pipeline_hard_event_summary_from_stdin <<'EOF'
[pipe 5s] udp_send_connected=10/s encrypt_worker_queue_full=2/s total=10 encrypt_worker_bulk_dropped=1.5/s total=7 decrypt_worker_queue_full=0/s total=0
[pipe 5s] connected_udp_kernel_dropped=0.7/s total=4 encrypt_worker_queue_full=3/s total=12 encrypt_worker_priority_queue_full=0.1/s total=1 encrypt_worker_bulk_queue_full=2.8/s total=11 fmp_linux_bulk_container_queue_full=0.4/s total=2 fmp_linux_bulk_container_queue_full_packets=25.8/s total=129 rx_loop_slow_maintenance_skipped=0.2/s total=1 decrypt_fsp_bulk_queue_full_fallback=0.5/s total=2 decrypt_fsp_open_worker_completion_backlog_fallback=0.3/s total=3 decrypt_fsp_worker_replay_dropped_too_old=0.4/s total=2 decrypt_fsp_worker_replay_dropped_too_old_lag_ge_2x_window=0.2/s total=1 fmp_aead_completion_aead_failed=0.2/s total=1 fsp_aead_completion_aead_failed=0.4/s total=2 fsp_aead_completion_epoch_mismatch=0.3/s total=3 fsp_aead_completion_replay_dropped_worker_open=0.8/s total=4 fsp_aead_completion_replay_dropped_duplicate=0.6/s total=3 fsp_aead_completion_replay_dropped_too_old=0.2/s total=1 fsp_aead_completion_replay_dropped_too_old_lag_ge_2x_window=0.2/s total=1 nvpn_tun_to_mesh_bulk_dropped=0/s total=0
[nvpn-pipe 5s] nvpn_tun_to_mesh_bulk_dropped=4/s total=8 nvpn_tun_to_mesh_bulk_dropped_batches=1/s total=2 nvpn_tun_to_mesh_bulk_dropped_packet_cap=4/s total=8 nvpn_tun_to_mesh_bulk_dropped_channel_full=0/s total=0
EOF
  )"
  assert_eq \
    "$got" \
    "connected_udp_kernel_dropped:max_rate_per_sec=0.7,total=4;encrypt_worker_queue_full:max_rate_per_sec=3,total=12;encrypt_worker_priority_queue_full:max_rate_per_sec=0.1,total=1;encrypt_worker_bulk_queue_full:max_rate_per_sec=2.8,total=11;encrypt_worker_bulk_dropped:max_rate_per_sec=1.5,total=7;fmp_linux_bulk_container_queue_full:max_rate_per_sec=0.4,total=2;fmp_linux_bulk_container_queue_full_packets:max_rate_per_sec=25.8,total=129;rx_loop_slow_maintenance_skipped:max_rate_per_sec=0.2,total=1;decrypt_fsp_bulk_queue_full_fallback:max_rate_per_sec=0.5,total=2;decrypt_fsp_open_worker_completion_backlog_fallback:max_rate_per_sec=0.3,total=3;decrypt_fsp_worker_replay_dropped_too_old:max_rate_per_sec=0.4,total=2;decrypt_fsp_worker_replay_dropped_too_old_lag_ge_2x_window:max_rate_per_sec=0.2,total=1;fmp_aead_completion_aead_failed:max_rate_per_sec=0.2,total=1;fsp_aead_completion_aead_failed:max_rate_per_sec=0.4,total=2;fsp_aead_completion_epoch_mismatch:max_rate_per_sec=0.3,total=3;fsp_aead_completion_replay_dropped_worker_open:max_rate_per_sec=0.8,total=4;fsp_aead_completion_replay_dropped_duplicate:max_rate_per_sec=0.6,total=3;fsp_aead_completion_replay_dropped_too_old:max_rate_per_sec=0.2,total=1;fsp_aead_completion_replay_dropped_too_old_lag_ge_2x_window:max_rate_per_sec=0.2,total=1;nvpn_tun_to_mesh_bulk_dropped:max_rate_per_sec=4,total=8;nvpn_tun_to_mesh_bulk_dropped_batches:max_rate_per_sec=1,total=2;nvpn_tun_to_mesh_bulk_dropped_packet_cap:max_rate_per_sec=4,total=8" \
    "pipeline hard event summary"

  got="$(
    pipeline_hard_event_summary_from_stdin 2 <<'EOF'
[pipe 5s] encrypt_worker_queue_full=4/s total=100 encrypt_worker_bulk_dropped=4/s total=50 fmp_linux_bulk_container_queue_full=0.2/s total=100 fmp_linux_bulk_container_queue_full_packets=10/s total=50 decrypt_fsp_open_worker_completion_backlog_fallback=0.1/s total=10 fsp_aead_completion_replay_dropped_worker_open=0.6/s total=20 fsp_aead_completion_replay_dropped_duplicate=0.8/s total=20 fsp_aead_completion_replay_dropped_too_old=0.1/s total=10 fsp_aead_completion_replay_dropped_too_old_lag_ge_2x_window=0.1/s total=7 fsp_aead_completion_replay_dropped_too_old_lag_ge_4x_window=0.1/s total=4
[nvpn-pipe 5s] nvpn_tun_to_mesh_bulk_dropped=2/s total=20 nvpn_tun_to_mesh_bulk_dropped_batches=0.5/s total=5 nvpn_tun_to_mesh_bulk_dropped_channel_full=2/s total=20
[pipe 5s] encrypt_worker_queue_full=3/s total=112 encrypt_worker_priority_queue_full=0.1/s total=1 encrypt_worker_bulk_queue_full=2.8/s total=11 encrypt_worker_bulk_dropped=1.5/s total=57 fmp_linux_bulk_container_queue_full=0.4/s total=102 fmp_linux_bulk_container_queue_full_packets=25.8/s total=179 rx_loop_slow_maintenance_skipped=0.2/s total=1 decrypt_fsp_open_worker_completion_backlog_fallback=0.5/s total=16 fsp_aead_completion_replay_dropped_worker_open=1/s total=24 fsp_aead_completion_replay_dropped_duplicate=1.4/s total=25 fsp_aead_completion_replay_dropped_too_old=0.4/s total=12 fsp_aead_completion_replay_dropped_too_old_lag_ge_2x_window=0.4/s total=10 fsp_aead_completion_replay_dropped_too_old_lag_ge_4x_window=0.2/s total=5
[nvpn-pipe 5s] nvpn_tun_to_mesh_bulk_dropped=4/s total=28 nvpn_tun_to_mesh_bulk_dropped_batches=1/s total=7 nvpn_tun_to_mesh_bulk_dropped_channel_full=4/s total=28
EOF
  )"
  assert_eq \
    "$got" \
    "encrypt_worker_queue_full:max_rate_per_sec=3,total=12;encrypt_worker_priority_queue_full:max_rate_per_sec=0.1,total=1;encrypt_worker_bulk_queue_full:max_rate_per_sec=2.8,total=11;encrypt_worker_bulk_dropped:max_rate_per_sec=1.5,total=7;fmp_linux_bulk_container_queue_full:max_rate_per_sec=0.4,total=2;fmp_linux_bulk_container_queue_full_packets:max_rate_per_sec=25.8,total=129;rx_loop_slow_maintenance_skipped:max_rate_per_sec=0.2,total=1;decrypt_fsp_open_worker_completion_backlog_fallback:max_rate_per_sec=0.5,total=6;fsp_aead_completion_replay_dropped_worker_open:max_rate_per_sec=1,total=4;fsp_aead_completion_replay_dropped_duplicate:max_rate_per_sec=1.4,total=5;fsp_aead_completion_replay_dropped_too_old:max_rate_per_sec=0.4,total=2;fsp_aead_completion_replay_dropped_too_old_lag_ge_2x_window:max_rate_per_sec=0.4,total=3;fsp_aead_completion_replay_dropped_too_old_lag_ge_4x_window:max_rate_per_sec=0.2,total=1;nvpn_tun_to_mesh_bulk_dropped:max_rate_per_sec=4,total=8;nvpn_tun_to_mesh_bulk_dropped_batches:max_rate_per_sec=1,total=2;nvpn_tun_to_mesh_bulk_dropped_channel_full:max_rate_per_sec=4,total=8" \
    "phase-scoped pipeline hard event summary subtracts pre-phase totals"
}

test_priority_hard_event_guard() {
  local got

  got="$(
    printf '%s\n' \
      "encrypt_worker_queue_full:max_rate_per_sec=3,total=12;encrypt_worker_bulk_queue_full:max_rate_per_sec=2.8,total=11;encrypt_worker_bulk_dropped:max_rate_per_sec=1.5,total=7" \
      | priority_hard_event_violations_from_summary
  )"
  assert_eq "$got" "" "bulk-only hard events do not violate priority guard"

  got="$(
    printf '%s\n' \
      "encrypt_worker_priority_queue_full:max_rate_per_sec=0.1,total=1;decrypt_fallback_priority_dropped:max_rate_per_sec=2,total=3;encrypt_worker_bulk_dropped:max_rate_per_sec=5,total=8" \
      | priority_hard_event_violations_from_summary
  )"
  assert_eq \
    "$got" \
    "encrypt_worker_priority_queue_full(total=1,max_rate_per_sec=0.1);decrypt_fallback_priority_dropped(total=3,max_rate_per_sec=2)" \
    "priority hard event violation summary"

  assert_fails_with \
    "priority hard event guard" \
    "fixture node-a priority/control hard events observed: encrypt_worker_priority_queue_full(total=1,max_rate_per_sec=0.1)" \
    bash -c 'source "$1"; FAIL_ON_PRIORITY_HARD_EVENTS=1; assert_no_priority_hard_events "fixture node-a" "encrypt_worker_priority_queue_full:max_rate_per_sec=0.1,total=1"' \
    bash "$PERF_SCRIPT"

  got="$(
    bash -c 'source "$1"; FAIL_ON_PRIORITY_HARD_EVENTS=0; assert_no_priority_hard_events "fixture node-a" "encrypt_worker_priority_queue_full:max_rate_per_sec=0.1,total=1"; printf ok' \
      bash "$PERF_SCRIPT"
  )"
  assert_eq "$got" "ok" "priority hard event guard opt-out"
}

test_priority_queue_wait_guard() {
  local got

  got="$(
    pipeline_priority_queue_wait_violations_from_stdin 10 <<'EOF'
[pipe 5s] fmp_worker_bulk_queue_wait=1000/s avg=1.1ms p50<=1.0ms p95<=2.1ms p99<=4.2ms max<=12.0ms allmax=12.0ms fmp_worker_priority_queue_wait=10/s avg=20.0us p50<=16.4us p95<=65.5us p99<=65.5us max<=131.1us allmax=2.1ms
[pipe 5s] decrypt_authenticated_session_priority_wait=1/s avg=30.0us p50<=32.8us p95<=65.5us p99<=65.5us max<=65.5us allmax=3.0ms
EOF
  )"
  assert_eq "$got" "" "bulk-only wait spikes do not violate priority wait guard"

  got="$(
    pipeline_priority_queue_wait_violations_from_stdin 10 <<'EOF'
[pipe 5s] endpoint_priority_event_wait=1/s avg=1.0ms p50<=1.0ms p95<=2.1ms p99<=4.2ms max<=16.8ms allmax=16.8ms fmp_worker_bulk_queue_wait=1000/s avg=1.1ms p50<=1.0ms p95<=2.1ms p99<=4.2ms max<=12.0ms allmax=12.0ms
[pipe 5s] decrypt_fsp_worker_priority_queue_wait=0.2/s avg=20.0ms p50<=16.8ms p95<=33.6ms p99<=33.6ms max<=67.1ms allmax=67.1ms
EOF
  )"
  assert_eq \
    "$got" \
    "endpoint_priority_event_wait(max_ms=16.8,p99_ms=4.2,rate_per_sec=1);decrypt_fsp_worker_priority_queue_wait(max_ms=67.1,p99_ms=33.6,rate_per_sec=0.2)" \
    "priority wait violation summary"

  got="$(
    pipeline_priority_queue_wait_violations_from_stdin 10 10 <<'EOF'
[pipe 5s] endpoint_priority_event_wait=6.8/s avg=2.8ms p50<=32.8us p95<=262.1us p99<=134.2ms max<=134.2ms fmp_worker_priority_queue_wait=4.6/s avg=45.1us p50<=65.5us p95<=131.1us p99<=262.1us max<=262.1us
EOF
  )"
  assert_eq "$got" "" "priority wait guard ignores low-rate tail samples"

  got="$(
    pipeline_priority_queue_wait_violations_from_stdin 10 10 <<'EOF'
[pipe 5s] endpoint_priority_event_wait=10/s avg=1.0ms p50<=1.0ms p95<=2.1ms p99<=4.2ms max<=16.8ms fmp_worker_priority_queue_wait=9.8/s avg=20.0us p50<=16.4us p95<=65.5us p99<=65.5us max<=131.1us
EOF
  )"
  assert_eq \
    "$got" \
    "endpoint_priority_event_wait(max_ms=16.8,p99_ms=4.2,rate_per_sec=10)" \
    "priority wait guard keeps sustained priority samples"

  assert_fails_with \
    "priority queue wait guard" \
    "fixture node-a priority queue waits exceeded 10ms at >=10/s: endpoint_priority_event_wait(max_ms=16.8,p99_ms=4.2,rate_per_sec=1)" \
    bash -c 'source "$1"; pipeline_priority_queue_wait_violations(){ printf "%s\n" "endpoint_priority_event_wait(max_ms=16.8,p99_ms=4.2,rate_per_sec=1)"; }; MAX_PRIORITY_QUEUE_WAIT_MS=10; assert_priority_queue_wait_ok "fixture node-a" node-a 0' \
    bash "$PERF_SCRIPT"

  got="$(
    bash -c 'source "$1"; pipeline_priority_queue_wait_violations(){ printf "should-not-run"; }; MAX_PRIORITY_QUEUE_WAIT_MS=0; assert_priority_queue_wait_ok "fixture node-a" node-a 0; printf ok' \
      bash "$PERF_SCRIPT"
  )"
  assert_eq "$got" "ok" "priority queue wait guard opt-out"
}

test_rx_maintenance_priority_queue_wait_threshold() {
  local got

  got="$(
    bash -c 'source "$1"; printf "%s" "$RX_MAINT_MAX_PRIORITY_QUEUE_WAIT_MS"' \
      bash "$PERF_SCRIPT"
  )"
  assert_eq "$got" "150" "rx-maintenance default priority wait threshold"

  got="$(
    NVPN_PERF_MAX_PRIORITY_QUEUE_WAIT_MS=0 \
      bash -c 'source "$1"; printf "%s" "$RX_MAINT_MAX_PRIORITY_QUEUE_WAIT_MS"' \
      bash "$PERF_SCRIPT"
  )"
  assert_eq "$got" "0" "rx-maintenance honors global priority wait opt-out"

  got="$(
    NVPN_PERF_RX_MAINT_MAX_PRIORITY_QUEUE_WAIT_MS=90 \
      bash -c 'source "$1"; printf "%s" "$RX_MAINT_MAX_PRIORITY_QUEUE_WAIT_MS"' \
      bash "$PERF_SCRIPT"
  )"
  assert_eq "$got" "90" "rx-maintenance priority wait threshold override"
}

test_phase_argument_selection() {
  local got

  got="$(
    bash -c '
      source "$1"
      parse_args --phase clean-underlay --phase rx-maintenance-fault
      validate_perf_phases
      phase_enabled unimpaired-underlay
      phase_enabled rx-maintenance-fault
      printf "ok\n"
    ' bash "$PERF_SCRIPT"
  )"
  assert_eq "$got" "ok" "legacy clean-underlay alias selection"

  got="$(bash "$PERF_SCRIPT" --list-phases)"
  assert_eq \
    "$got" \
    $'unimpaired-underlay\nconstrained-underlay\nrx-maintenance-fault\nalias: clean-underlay=unimpaired-underlay' \
    "phase list includes canonical names and alias"

  got="$(
    bash -c '
      source "$1"
      parse_args --phases " rx-maintenance-fault , constrained-underlay "
      validate_perf_phases
      printf "%s\n" "$PERF_PHASES"
    ' bash "$PERF_SCRIPT"
  )"
  assert_eq "$got" " rx-maintenance-fault , constrained-underlay " "--phases selection"

  assert_fails_with \
    "unknown phase argument" \
    "NVPN_PERF_PHASES contains unknown phase: nope" \
    bash -c 'source "$1"; parse_args --phase nope; validate_perf_phases' \
    bash "$PERF_SCRIPT"
}

test_phase_summary_pipeline_columns() {
  local dir header_fields row_fields top_a top_b batch_a batch_b spread_a spread_b decrypt_batch_a decrypt_batch_b decrypt_spread_a decrypt_spread_b decrypt_turn_mix_a decrypt_turn_mix_b linux_bulk_a linux_bulk_b udp_send_a udp_send_b hard_a hard_b raw_a raw_b
  dir="$(mktemp -d)"

  (
    PERF_OUTPUT_DIR="$dir"
    init_phase_summary >/dev/null
    append_phase_summary \
      "fixture-phase" \
      "1" \
      "2" \
      "3" \
      "4" \
      "5" \
      "6" \
      "0" \
      "1.1" \
      "2.2" \
      "3.3" \
      "4.4" \
      "7" \
      "8" \
      "0" \
      "1.5" \
      "2.5" \
      "3.5" \
      "4.5" \
      "0" \
      "1.6" \
      "2.6" \
      "3.6" \
      "4.6" \
      "100" \
      "200" \
      "decrypt_fallback_bulk_wait:rate_per_sec=10,p95_ms=2.1,p99_ms=8.4,max_ms=16.8,allmax_ms=11.1" \
      "fmp_worker_queue_wait:rate_per_sec=20,p95_ms=1,p99_ms=2.1,max_ms=2.1,allmax_ms=2" \
      "avg_packets=42.0,full_pct=90.0,single_pct=5.0,priority_pct=25.0,bulk_pct=75.0,flush_per_sec=10,packets_per_sec=420,priority_packets_per_sec=105,bulk_packets_per_sec=315" \
      "avg_packets=31.5,full_pct=60.0,single_pct=2.0,priority_pct=40.0,bulk_pct=60.0,flush_per_sec=20,packets_per_sec=630,priority_packets_per_sec=252,bulk_packets_per_sec=378" \
      "active_workers=2,workers_ge1pct=2,top_worker=w7,top_pct=66.5,flow_keyed_pct=100.0,target_only_pct=0.0,total_per_sec=416349,worker_rates=w4:139503;w7:276846" \
      "active_workers=1,workers_ge1pct=1,top_worker=w3,top_pct=100.0,flow_keyed_pct=0.0,target_only_pct=100.0,total_per_sec=19384.6,worker_rates=w3:19384.6" \
      "avg_packets=32.0,full_pct=25.0,single_pct=10.0,priority_pct=10.0,bulk_pct=90.0,flush_per_sec=20,packets_per_sec=640,priority_packets_per_sec=64,bulk_packets_per_sec=576" \
      "avg_packets=16.0,full_pct=12.5,single_pct=4.0,priority_pct=25.0,bulk_pct=75.0,flush_per_sec=30,packets_per_sec=480,priority_packets_per_sec=120,bulk_packets_per_sec=360" \
      "active_workers=2,workers_ge1pct=2,top_worker=w0,top_pct=75.0,total_packets_per_sec=640,worker_packet_rates=w0:480;w2:160" \
      "active_workers=1,workers_ge1pct=1,top_worker=w3,top_pct=100.0,total_packets_per_sec=480,worker_packet_rates=w3:480" \
      "completion_packet_pct=32.4,completion_batches_per_sec=14,known_completion_packets_per_sec=384,bulk_packets_per_sec=800,select_fmp_completion_batches_per_sec=2,select_fsp_completion_batches_per_sec=3,select_fsp_completion_packets_per_sec=96,select_bulk_packets_per_sec=480,drain_completion_batches_per_sec=4,drain_completion_packets_per_sec=128,drain_bulk_packets_per_sec=320,interleave_completion_batches_per_sec=5,interleave_completion_packets_per_sec=160,interleave_budget_exhausted_per_sec=0.2" \
      "completion_packet_pct=20.0,completion_batches_per_sec=7,known_completion_packets_per_sec=120,bulk_packets_per_sec=480,select_fmp_completion_batches_per_sec=1,select_fsp_completion_batches_per_sec=2,select_fsp_completion_packets_per_sec=40,select_bulk_packets_per_sec=240,drain_completion_batches_per_sec=2,drain_completion_packets_per_sec=40,drain_bulk_packets_per_sec=240,interleave_completion_batches_per_sec=2,interleave_completion_packets_per_sec=40,interleave_budget_exhausted_per_sec=0" \
      "avg_packets=96.0,avg_sent_packets=96.0,enqueued_per_sec=5,packets_per_sec=480,sent_per_sec=5,sent_packets_per_sec=480,queue_p95_ms=0.524,queue_p99_ms=1" \
      "avg_packets=48.0,avg_sent_packets=48.0,enqueued_per_sec=10,packets_per_sec=480,sent_per_sec=10,sent_packets_per_sec=480,queue_p95_ms=0.262,queue_p99_ms=0.524" \
      "gso_packet_pct=99.1,sendmmsg_packet_pct=0.9,avg_packets=35.3,gso_avg_packets=42.0,sendmmsg_avg_packets=2.0,gso_batch_per_sec=10,gso_packets_per_sec=420,sendmmsg_batch_per_sec=2,sendmmsg_packets_per_sec=4,total_packets_per_sec=424" \
      "gso_packet_pct=0.0,sendmmsg_packet_pct=100.0,avg_packets=2.0,gso_avg_packets=0.0,sendmmsg_avg_packets=2.0,gso_batch_per_sec=0,gso_packets_per_sec=0,sendmmsg_batch_per_sec=12.5,sendmmsg_packets_per_sec=25,total_packets_per_sec=25" \
      "encrypt_worker_queue_full:max_rate_per_sec=3,total=12" \
      "decrypt_worker_bulk_dropped:max_rate_per_sec=1,total=4" \
      "[pipe node-a]" \
      "[pipe node-b]"
    append_phase_note "unimpaired-underlay"
  )

  header_fields="$(awk -F '\t' 'NR == 1 { print NF }' "$dir/phase-summary.tsv")"
  row_fields="$(awk -F '\t' 'NR == 2 { print NF }' "$dir/phase-summary.tsv")"
  assert_eq "$header_fields" "46" "phase summary header field count"
  assert_eq "$row_fields" "46" "phase summary row field count"

  top_a="$(awk -F '\t' 'NR == 2 { print $27 }' "$dir/phase-summary.tsv")"
  top_b="$(awk -F '\t' 'NR == 2 { print $28 }' "$dir/phase-summary.tsv")"
  batch_a="$(awk -F '\t' 'NR == 2 { print $29 }' "$dir/phase-summary.tsv")"
  batch_b="$(awk -F '\t' 'NR == 2 { print $30 }' "$dir/phase-summary.tsv")"
  spread_a="$(awk -F '\t' 'NR == 2 { print $31 }' "$dir/phase-summary.tsv")"
  spread_b="$(awk -F '\t' 'NR == 2 { print $32 }' "$dir/phase-summary.tsv")"
  decrypt_batch_a="$(awk -F '\t' 'NR == 2 { print $33 }' "$dir/phase-summary.tsv")"
  decrypt_batch_b="$(awk -F '\t' 'NR == 2 { print $34 }' "$dir/phase-summary.tsv")"
  decrypt_spread_a="$(awk -F '\t' 'NR == 2 { print $35 }' "$dir/phase-summary.tsv")"
  decrypt_spread_b="$(awk -F '\t' 'NR == 2 { print $36 }' "$dir/phase-summary.tsv")"
  decrypt_turn_mix_a="$(awk -F '\t' 'NR == 2 { print $37 }' "$dir/phase-summary.tsv")"
  decrypt_turn_mix_b="$(awk -F '\t' 'NR == 2 { print $38 }' "$dir/phase-summary.tsv")"
  linux_bulk_a="$(awk -F '\t' 'NR == 2 { print $39 }' "$dir/phase-summary.tsv")"
  linux_bulk_b="$(awk -F '\t' 'NR == 2 { print $40 }' "$dir/phase-summary.tsv")"
  udp_send_a="$(awk -F '\t' 'NR == 2 { print $41 }' "$dir/phase-summary.tsv")"
  udp_send_b="$(awk -F '\t' 'NR == 2 { print $42 }' "$dir/phase-summary.tsv")"
  hard_a="$(awk -F '\t' 'NR == 2 { print $43 }' "$dir/phase-summary.tsv")"
  hard_b="$(awk -F '\t' 'NR == 2 { print $44 }' "$dir/phase-summary.tsv")"
  raw_a="$(awk -F '\t' 'NR == 2 { print $45 }' "$dir/phase-summary.tsv")"
  raw_b="$(awk -F '\t' 'NR == 2 { print $46 }' "$dir/phase-summary.tsv")"
  assert_eq "$top_a" "decrypt_fallback_bulk_wait:rate_per_sec=10,p95_ms=2.1,p99_ms=8.4,max_ms=16.8,allmax_ms=11.1" "phase summary node-a top queue wait"
  assert_eq "$top_b" "fmp_worker_queue_wait:rate_per_sec=20,p95_ms=1,p99_ms=2.1,max_ms=2.1,allmax_ms=2" "phase summary node-b top queue wait"
  assert_eq "$batch_a" "avg_packets=42.0,full_pct=90.0,single_pct=5.0,priority_pct=25.0,bulk_pct=75.0,flush_per_sec=10,packets_per_sec=420,priority_packets_per_sec=105,bulk_packets_per_sec=315" "phase summary node-a FMP worker batch"
  assert_eq "$batch_b" "avg_packets=31.5,full_pct=60.0,single_pct=2.0,priority_pct=40.0,bulk_pct=60.0,flush_per_sec=20,packets_per_sec=630,priority_packets_per_sec=252,bulk_packets_per_sec=378" "phase summary node-b FMP worker batch"
  assert_eq "$spread_a" "active_workers=2,workers_ge1pct=2,top_worker=w7,top_pct=66.5,flow_keyed_pct=100.0,target_only_pct=0.0,total_per_sec=416349,worker_rates=w4:139503;w7:276846" "phase summary node-a FMP worker dispatch spread"
  assert_eq "$spread_b" "active_workers=1,workers_ge1pct=1,top_worker=w3,top_pct=100.0,flow_keyed_pct=0.0,target_only_pct=100.0,total_per_sec=19384.6,worker_rates=w3:19384.6" "phase summary node-b FMP worker dispatch spread"
  assert_eq "$decrypt_batch_a" "avg_packets=32.0,full_pct=25.0,single_pct=10.0,priority_pct=10.0,bulk_pct=90.0,flush_per_sec=20,packets_per_sec=640,priority_packets_per_sec=64,bulk_packets_per_sec=576" "phase summary node-a decrypt worker batch"
  assert_eq "$decrypt_batch_b" "avg_packets=16.0,full_pct=12.5,single_pct=4.0,priority_pct=25.0,bulk_pct=75.0,flush_per_sec=30,packets_per_sec=480,priority_packets_per_sec=120,bulk_packets_per_sec=360" "phase summary node-b decrypt worker batch"
  assert_eq "$decrypt_spread_a" "active_workers=2,workers_ge1pct=2,top_worker=w0,top_pct=75.0,total_packets_per_sec=640,worker_packet_rates=w0:480;w2:160" "phase summary node-a decrypt worker spread"
  assert_eq "$decrypt_spread_b" "active_workers=1,workers_ge1pct=1,top_worker=w3,top_pct=100.0,total_packets_per_sec=480,worker_packet_rates=w3:480" "phase summary node-b decrypt worker spread"
  assert_eq "$decrypt_turn_mix_a" "completion_packet_pct=32.4,completion_batches_per_sec=14,known_completion_packets_per_sec=384,bulk_packets_per_sec=800,select_fmp_completion_batches_per_sec=2,select_fsp_completion_batches_per_sec=3,select_fsp_completion_packets_per_sec=96,select_bulk_packets_per_sec=480,drain_completion_batches_per_sec=4,drain_completion_packets_per_sec=128,drain_bulk_packets_per_sec=320,interleave_completion_batches_per_sec=5,interleave_completion_packets_per_sec=160,interleave_budget_exhausted_per_sec=0.2" "phase summary node-a decrypt worker turn mix"
  assert_eq "$decrypt_turn_mix_b" "completion_packet_pct=20.0,completion_batches_per_sec=7,known_completion_packets_per_sec=120,bulk_packets_per_sec=480,select_fmp_completion_batches_per_sec=1,select_fsp_completion_batches_per_sec=2,select_fsp_completion_packets_per_sec=40,select_bulk_packets_per_sec=240,drain_completion_batches_per_sec=2,drain_completion_packets_per_sec=40,drain_bulk_packets_per_sec=240,interleave_completion_batches_per_sec=2,interleave_completion_packets_per_sec=40,interleave_budget_exhausted_per_sec=0" "phase summary node-b decrypt worker turn mix"
  assert_eq "$linux_bulk_a" "avg_packets=96.0,avg_sent_packets=96.0,enqueued_per_sec=5,packets_per_sec=480,sent_per_sec=5,sent_packets_per_sec=480,queue_p95_ms=0.524,queue_p99_ms=1" "phase summary node-a Linux bulk container"
  assert_eq "$linux_bulk_b" "avg_packets=48.0,avg_sent_packets=48.0,enqueued_per_sec=10,packets_per_sec=480,sent_per_sec=10,sent_packets_per_sec=480,queue_p95_ms=0.262,queue_p99_ms=0.524" "phase summary node-b Linux bulk container"
  assert_eq "$udp_send_a" "gso_packet_pct=99.1,sendmmsg_packet_pct=0.9,avg_packets=35.3,gso_avg_packets=42.0,sendmmsg_avg_packets=2.0,gso_batch_per_sec=10,gso_packets_per_sec=420,sendmmsg_batch_per_sec=2,sendmmsg_packets_per_sec=4,total_packets_per_sec=424" "phase summary node-a UDP send batch"
  assert_eq "$udp_send_b" "gso_packet_pct=0.0,sendmmsg_packet_pct=100.0,avg_packets=2.0,gso_avg_packets=0.0,sendmmsg_avg_packets=2.0,gso_batch_per_sec=0,gso_packets_per_sec=0,sendmmsg_batch_per_sec=12.5,sendmmsg_packets_per_sec=25,total_packets_per_sec=25" "phase summary node-b UDP send batch"
  assert_eq "$hard_a" "encrypt_worker_queue_full:max_rate_per_sec=3,total=12" "phase summary node-a hard events"
  assert_eq "$hard_b" "decrypt_worker_bulk_dropped:max_rate_per_sec=1,total=4" "phase summary node-b hard events"
  assert_eq "$raw_a" "[pipe node-a]" "phase summary node-a raw pipeline"
  assert_eq "$raw_b" "[pipe node-b]" "phase summary node-b raw pipeline"
  assert_file_contains "$dir/phase-notes.tsv" "unimpaired-underlay" "phase notes canonical unimpaired lane"
  assert_file_contains "$dir/phase-notes.tsv" "not the peak perf-docker.sh clean throughput lane" "phase notes explains loaded lane"

  rm -rf "$dir"
}

test_start_compose_services_supports_skip_build() {
  local calls
  calls="$(mktemp)"

  (
    source "$PERF_SCRIPT"
    COMPOSE=(record_compose_call)
    record_compose_call() {
      printf '%s\n' "$*" >>"$calls"
    }

    SKIP_BUILD=0
    start_compose_services
  )
  assert_eq "$(cat "$calls")" $'build node-a node-b\nup -d node-a node-b' "default compose startup"

  : >"$calls"
  (
    source "$PERF_SCRIPT"
    COMPOSE=(record_compose_call)
    record_compose_call() {
      printf '%s\n' "$*" >>"$calls"
    }

    SKIP_BUILD=1
    start_compose_services
  )
  assert_eq "$(cat "$calls")" "up -d --no-build node-a node-b" "skip-build compose startup"

  rm -f "$calls"
}

test_roaming_network_change_rebind_log_contract() {
  python3 - "$ROOT_DIR/scripts/e2e-fips-roaming-docker.sh" <<'PY'
import pathlib
import subprocess
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
section = source[
    source.index("wait_for_network_change_rebind_after_marker() {"):
    source.index("\nmark_daemon_log() {")
]
program = section.split('awk -v marker="$marker" \'\n', 1)[1].split(
    "\n' /root/.config/nvpn/daemon.log",
    1,
)[0]


def accepts(*lines):
    return subprocess.run(
        ["awk", "-v", "marker=fixture-cut", program],
        input="\n".join(lines) + "\n",
        text=True,
        check=False,
    ).returncode == 0


marker = "NVPN_E2E_MARKER fixture-cut"
change = "daemon: network change detected; refreshing FIPS endpoint state"
rebound = (
    "daemon: FIPS underlay carrier(s) rebound on utun100 "
    "after network change (2)"
)
restart = "daemon: restarted FIPS private mesh on utun100"

if not accepts(marker, change, rebound):
    raise SystemExit("ordered nonzero rebind receipt was rejected")
for invalid in (
    (marker, rebound, change),
    (marker, change, rebound.replace("(2)", "(0)")),
    (marker, change),
    (marker, change, rebound, restart),
    (change, rebound, marker),
):
    if accepts(*invalid):
        raise SystemExit(f"invalid network-change receipts were accepted: {invalid}")
PY
}

test_roaming_network_change_probe_keeps_failure_budget_calibrated() {
  python3 - "$ROOT_DIR/scripts/e2e-fips-roaming-docker.sh" <<'PY'
import pathlib
import re
import sys

source = pathlib.Path(sys.argv[1]).read_text(encoding="utf-8")
if 'NETWORK_CHANGE_PAYLOAD_PROBE_INTERVAL_SECS="${NVPN_E2E_NETWORK_CHANGE_PAYLOAD_PROBE_INTERVAL_SECS:-1}"' not in source:
    raise SystemExit("network-change probe interval is not independently calibrated")

section = source[
    source.index("run_underlay_network_change() {"):
    source.index("\ncleanup\n", source.index("run_underlay_network_change() {"))
]
calls = re.findall(r"start_payload_probe\s+node-[ab][^\n]+", section)
if len(calls) != 2:
    raise SystemExit(f"expected two network-change payload probes, found {calls}")
for call in calls:
    if not call.endswith('"$NETWORK_CHANGE_PAYLOAD_PROBE_INTERVAL_SECS"'):
        raise SystemExit(f"network-change payload probe uses the flap cadence: {call}")
PY
}

test_dockerfile_supports_local_base_images() {
  local dockerfile="$ROOT_DIR/Dockerfile.e2e"
  local paid_exit_dockerfile="$ROOT_DIR/Dockerfile.paid-exit-e2e"
  local compose

  assert_file_not_contains "$dockerfile" "syntax=docker/dockerfile" "Dockerfile external frontend directive"
  assert_file_contains "$dockerfile" "ARG NVPN_E2E_BUILDER_IMAGE=rust:1.93-bookworm" "builder image arg"
  assert_file_contains "$dockerfile" 'FROM ${NVPN_E2E_BUILDER_IMAGE} AS builder' "builder image from"
  assert_file_contains "$dockerfile" "ARG NVPN_E2E_RUNTIME_IMAGE=debian:bookworm-slim" "runtime image arg"
  assert_file_contains "$dockerfile" 'FROM ${NVPN_E2E_RUNTIME_IMAGE} AS runtime' "runtime image from"
  assert_file_contains "$dockerfile" "ARG NVPN_E2E_BUILDER_APT_INSTALL=1" "builder apt arg"
  assert_file_contains "$dockerfile" "ARG NVPN_E2E_RUNTIME_APT_INSTALL=1" "runtime apt arg"
  assert_file_contains "$dockerfile" "COPY vendor ./vendor" "vendored Cashu source copy"
  assert_file_contains "$paid_exit_dockerfile" "COPY vendor ./vendor" "paid-exit vendored Cashu source copy"
  assert_file_contains "$dockerfile" "[patch.crates-io]" "local FIPS Cargo patch table"
  assert_file_contains "$dockerfile" 'nvpn-fips-core = { path = "/app/fips/crates/fips-core" }' "renamed local FIPS core patch"
  assert_file_contains "$dockerfile" 'nvpn-fips-endpoint = { path = "/app/fips/crates/fips-endpoint" }' "renamed local FIPS endpoint patch"
  assert_file_contains "$dockerfile" 'nvpn-fips-identity = { path = "/app/fips/crates/fips-identity" }' "renamed local FIPS identity patch"
  assert_file_contains "$paid_exit_dockerfile" 'nvpn-fips-core = { path = "/app/fips/crates/fips-core" }' "paid-exit renamed local FIPS core patch"
  assert_file_contains "$paid_exit_dockerfile" 'nvpn-fips-endpoint = { path = "/app/fips/crates/fips-endpoint" }' "paid-exit renamed local FIPS endpoint patch"
  assert_file_contains "$paid_exit_dockerfile" 'nvpn-fips-identity = { path = "/app/fips/crates/fips-identity" }' "paid-exit renamed local FIPS identity patch"

  for compose in \
    "$ROOT_DIR/docker-compose.e2e.yml" \
    "$ROOT_DIR/docker-compose.exit-node-e2e.yml" \
    "$ROOT_DIR/docker-compose.wireguard-exit-e2e.yml"; do
    assert_file_contains "$compose" 'NVPN_E2E_BUILDER_IMAGE: ${NVPN_E2E_BUILDER_IMAGE:-rust:1.93-bookworm}' "compose builder image arg"
    assert_file_contains "$compose" 'NVPN_E2E_RUNTIME_IMAGE: ${NVPN_E2E_RUNTIME_IMAGE:-debian:bookworm-slim}' "compose runtime image arg"
    assert_file_contains "$compose" 'NVPN_E2E_BUILDER_APT_INSTALL: ${NVPN_E2E_BUILDER_APT_INSTALL:-1}' "compose builder apt arg"
    assert_file_contains "$compose" 'NVPN_E2E_RUNTIME_APT_INSTALL: ${NVPN_E2E_RUNTIME_APT_INSTALL:-1}' "compose runtime apt arg"
  done

  assert_file_contains "$ROOT_DIR/docker-compose.exit-node-e2e.yml" \
    'image: ${NVPN_EXIT_NODE_E2E_IMAGE:-nostr-vpn-e2e-node}' \
    "exit-node fixtures share the release-gate node image"
  assert_file_contains "$ROOT_DIR/docker-compose.wireguard-exit-e2e.yml" \
    'image: ${NVPN_E2E_NODE_IMAGE:-nostr-vpn-e2e-node}' \
    "WireGuard fixtures share the release-gate node image"
  for script in \
    "$ROOT_DIR/scripts/e2e-fips-routed-udp-docker.sh" \
    "$ROOT_DIR/scripts/e2e-fips-roaming-docker.sh" \
    "$ROOT_DIR/scripts/e2e-fips-nat-safe-mtu-docker.sh" \
    "$ROOT_DIR/scripts/e2e-wireguard-exit-docker.sh" \
    "$ROOT_DIR/scripts/e2e-wireguard-exit-userspace-docker.sh"; do
    assert_file_contains "$script" "NVPN_E2E_SKIP_NODE_BUILD" \
      "functional Docker gate can reuse the release-gate node image"
    assert_file_contains "$script" "up -d --no-build" \
      "functional Docker gate prevents an implicit rebuild"
  done
}

test_perf_harness_supports_cpu_stress() {
  assert_file_contains "$PERF_SCRIPT" 'source "$SUMMARY_LIB"' "perf harness sources docker bench helpers"
  assert_file_contains "$PERF_SCRIPT" 'PIPELINE_INTERVAL_SECS="${NVPN_PERF_PIPELINE_INTERVAL_SECS:-5}"' "perf harness configurable pipeline interval"
  assert_file_contains "$PERF_SCRIPT" "FIPS_PERF_INTERVAL_SECS='\$PIPELINE_INTERVAL_SECS'" "perf harness propagates FIPS pipeline interval"
  assert_file_contains "$PERF_SCRIPT" "write_perf_metadata" "perf harness writes benchmark metadata"
  assert_file_contains "$PERF_SCRIPT" "NVPN_PERF_PIPELINE_INTERVAL_SECS=1" "perf harness pipeline interval help example"
  assert_file_contains "$PERF_SCRIPT" "NVPN_PERF_MAX_TCP_RETRANS=1000" "perf harness retransmit ceiling help example"
  assert_file_contains "$PERF_SCRIPT" "NVPN_PERF_MAX_PRIORITY_QUEUE_WAIT_MS=0" "perf harness priority wait opt-out help example"
  assert_file_contains "$PERF_SCRIPT" "NVPN_PERF_MIN_PRIORITY_QUEUE_WAIT_RATE_PER_SEC=0" "perf harness priority wait rate opt-out help example"
  assert_file_contains "$PERF_SCRIPT" "docker_bench_stop_cpu_stress" "perf harness stops docker CPU stress"
  assert_file_contains "$PERF_SCRIPT" "docker_bench_start_cpu_stress" "perf harness starts docker CPU stress"
  assert_file_contains "$PERF_SCRIPT" "NVPN_DOCKER_CPU_STRESS=1 NVPN_DOCKER_CPU_STRESS_SIDES=remote" "perf harness CPU stress help example"
}

test_perf_metadata_maps_e2e_env() {
  local dir metadata
  dir="$(mktemp -d)"
  metadata="$dir/metadata.env"

  (
    PERF_OUTPUT_DIR="$dir"
    PIPELINE_TRACE=1
    PIPELINE_INTERVAL_SECS=2
    EXTRA_ENV="FIPS_LINUX_BULK_CONTAINERS=1"
    DURATION=3
    docker_bench_write_metadata() {
      printf 'backend=%s\n' "$1" >"$metadata"
      printf 'duration=%s\n' "$2" >>"$metadata"
      printf 'output_dir=%s\n' "$OUTPUT_DIR" >>"$metadata"
      printf 'trace=%s\n' "$NVPN_DOCKER_PIPELINE_TRACE" >>"$metadata"
      printf 'trace_interval=%s\n' "$NVPN_DOCKER_PIPELINE_INTERVAL_SECS" >>"$metadata"
      printf 'extra_env=%s\n' "$NVPN_DOCKER_EXTRA_ENV" >>"$metadata"
    }
    write_perf_metadata
  )

  assert_file_contains "$metadata" "backend=nvpn" "metadata backend"
  assert_file_contains "$metadata" "duration=3" "metadata duration"
  assert_file_contains "$metadata" "output_dir=$dir" "metadata output dir"
  assert_file_contains "$metadata" "trace=1" "metadata trace mapping"
  assert_file_contains "$metadata" "trace_interval=2" "metadata trace interval mapping"
  assert_file_contains "$metadata" "extra_env=FIPS_LINUX_BULK_CONTAINERS=1" "metadata extra env mapping"

  rm -rf "$dir"
}

test_failure_summary_context() {
  local dir header_prefix header_fields row_fields row_phase row_step row_forward row_direct_a row_direct_b row_pipeline_a row_pipeline_b
  dir="$(mktemp -d)"

  (
    PERF_OUTPUT_DIR="$dir"
    init_phase_summary >/dev/null
    direct_underlay_bytes() {
      case "$1" in
        node-a) printf '150\n' ;;
        node-b) printf '240\n' ;;
        *) printf '0\n' ;;
      esac
    }
    peak_wait_pipeline_line() {
      printf '[pipe %s queue_full=1 drop=0]\n' "$1"
    }

    CURRENT_PHASE="fixture-phase"
    CURRENT_STEP="fixture-step"
    CURRENT_FORWARD_MBIT="123.4"
    CURRENT_FORWARD_RETRANS="7"
    CURRENT_REVERSE_MBIT="234.5"
    CURRENT_REVERSE_RETRANS="8"
    CURRENT_PROBE_MBIT="111.1"
    CURRENT_PROBE_RETRANS="9"
    CURRENT_PING_LOSS="0"
    CURRENT_PING_AVG="1.2"
    CURRENT_PING_P95="3.4"
    CURRENT_PING_P99="5.6"
    CURRENT_PING_MAX="7.8"
    CURRENT_DIRECT_BEFORE_A="100"
    CURRENT_DIRECT_BEFORE_B="200"
    append_failure_summary "fixture throughput" ">=" "99" "100"
  )

  header_prefix="$(awk -F '\t' 'NR == 1 { print $1 "\t" $2 "\t" $3 "\t" $4 }' "$dir/failure-summary.tsv")"
  assert_eq "$header_prefix" $'label\tcomparison\tactual\tthreshold' "failure summary prefix"

  header_fields="$(awk -F '\t' 'NR == 1 { print NF }' "$dir/failure-summary.tsv")"
  row_fields="$(awk -F '\t' 'NR == 2 { print NF }' "$dir/failure-summary.tsv")"
  assert_eq "$header_fields" "21" "failure summary header field count"
  assert_eq "$row_fields" "21" "failure summary row field count"

  row_phase="$(awk -F '\t' 'NR == 2 { print $5 }' "$dir/failure-summary.tsv")"
  row_step="$(awk -F '\t' 'NR == 2 { print $6 }' "$dir/failure-summary.tsv")"
  row_forward="$(awk -F '\t' 'NR == 2 { print $7 }' "$dir/failure-summary.tsv")"
  row_direct_a="$(awk -F '\t' 'NR == 2 { print $18 }' "$dir/failure-summary.tsv")"
  row_direct_b="$(awk -F '\t' 'NR == 2 { print $19 }' "$dir/failure-summary.tsv")"
  row_pipeline_a="$(awk -F '\t' 'NR == 2 { print $20 }' "$dir/failure-summary.tsv")"
  row_pipeline_b="$(awk -F '\t' 'NR == 2 { print $21 }' "$dir/failure-summary.tsv")"
  assert_eq "$row_phase" "fixture-phase" "failure summary phase"
  assert_eq "$row_step" "fixture-step" "failure summary step"
  assert_eq "$row_forward" "123.4" "failure summary forward Mbps"
  assert_eq "$row_direct_a" "50" "failure summary node-a direct delta"
  assert_eq "$row_direct_b" "40" "failure summary node-b direct delta"
  assert_eq "$row_pipeline_a" "[pipe node-a queue_full=1 drop=0]" "failure summary node-a pipeline"
  assert_eq "$row_pipeline_b" "[pipe node-b queue_full=1 drop=0]" "failure summary node-b pipeline"

  rm -rf "$dir"
}

test_raw_artifact_helpers() {
  local dir path content copied_content server_interval_content
  dir="$(mktemp -d)"

  (
    PERF_OUTPUT_DIR="$dir"
    assert_eq "$(artifact_slug 'rx maintenance/fault')" "rx-maintenance-fault" "artifact phase slug"
    assert_eq "$(artifact_slug 'Forward TCP load ping')" "forward-tcp-load-ping" "artifact step slug"

    path="$(perf_artifact_path 'rx maintenance/fault' 'Forward TCP load ping' 'ping.txt')"
    assert_eq "$path" "$dir/raw/rx-maintenance-fault-forward-tcp-load-ping.ping.txt" "artifact path"

    write_perf_artifact 'rx maintenance/fault' 'Forward TCP load ping' 'ping.txt' 'ping payload'
    content="$(cat "$path")"
    assert_eq "$content" "ping payload" "written raw ping artifact"

    content="$(mktemp)"
    printf '%s\n' '{"end":true}' >"$content"
    copy_perf_artifact 'rx maintenance/fault' 'forward TCP load' 'iperf.json' "$content"
    copied_content="$(cat "$dir/raw/rx-maintenance-fault-forward-tcp-load.iperf.json")"
    assert_eq "$copied_content" '{"end":true}' "copied raw iperf artifact"
    rm -f "$content"

    write_iperf_server_artifacts \
      'rx maintenance/fault' \
      'reverse TCP' \
      "$(fixture_iperf_with_server_output)"
    assert_file_contains \
      "$dir/raw/rx-maintenance-fault-reverse-tcp-server.iperf.json" \
      '"intervals"' \
      "server iperf JSON artifact"
    server_interval_content="$(cat "$dir/raw/rx-maintenance-fault-reverse-tcp-server-intervals.tsv")"
    assert_eq \
      "$server_interval_content" \
      $'interval\tomitted\tstart_sec\tend_sec\tmbps\tretransmits\tsnd_cwnd_bytes\trtt_us\trttvar_us\n0\tfalse\t0\t1\t234.6\t9\t777\t888\t99' \
      "server iperf interval artifact"

    write_iperf_sender_artifacts \
      'rx maintenance/fault' \
      'reverse TCP' \
      "$(fixture_iperf_with_server_output)"
    sender_interval_content="$(cat "$dir/raw/rx-maintenance-fault-reverse-tcp-sender-intervals.tsv")"
    assert_eq \
      "$sender_interval_content" \
      $'interval\tomitted\tstart_sec\tend_sec\tmbps\tretransmits\tsnd_cwnd_bytes\trtt_us\trttvar_us\n0\tfalse\t0\t1\t234.6\t9\t777\t888\t99' \
      "sender iperf interval artifact"
    sender_summary_content="$(cat "$dir/raw/rx-maintenance-fault-reverse-tcp-sender-summary.tsv")"
    assert_eq \
      "$sender_summary_content" \
      $'intervals\tmbps_min\tmbps_max\tretransmits_total\tretransmits_max_interval\tsnd_cwnd_min_bytes\trtt_max_us\trttvar_max_us\n1\t234.6\t234.6\t9\t9\t777\t888\t99' \
      "sender iperf summary artifact"
  )

  rm -rf "$dir"
}

test_selected_pipeline_summary_artifact() {
  local dir node_a_path node_b_path empty_path
  dir="$(mktemp -d)"

  (
    PERF_OUTPUT_DIR="$dir"
    write_selected_pipeline_summary \
      "unimpaired-underlay" \
      "node-a" \
      "[pipe node-a selected]"
    write_selected_pipeline_summary \
      "unimpaired-underlay" \
      "node-b" \
      "[pipe node-b selected] | [nvpn-pipe node-b selected]"
    write_selected_pipeline_summary "unimpaired-underlay" "node-c" ""
  )

  node_a_path="$dir/raw/unimpaired-underlay-node-a-selected-pipeline.txt"
  node_b_path="$dir/raw/unimpaired-underlay-node-b-selected-pipeline.txt"
  empty_path="$dir/raw/unimpaired-underlay-node-c-selected-pipeline.txt"
  assert_eq "$(cat "$node_a_path")" "[pipe node-a selected]" "selected node-a pipeline artifact"
  assert_eq "$(cat "$node_b_path")" "[pipe node-b selected] | [nvpn-pipe node-b selected]" "selected node-b pipeline artifact"
  if [[ -e "$empty_path" ]]; then
    fail "empty selected pipeline artifact should not be written"
  fi

  rm -rf "$dir"
}

test_nvpn_perf_docker_phase_summary_hooks() {
  local script="$ROOT_DIR/scripts/perf-docker.sh"
  local summary_lib="$ROOT_DIR/scripts/lib-docker-bench-summary.sh"
  assert_file_contains "$script" "nvpn-pipeline-phase-ranges.tsv" "nvpn perf phase range artifact"
  assert_file_contains "$script" "nvpn-pipeline-phase-summary.tsv" "nvpn perf phase summary artifact"
  assert_file_contains "$script" "run_test_json tcp-single" "nvpn perf TCP single phase range"
  assert_file_contains "$script" "write_pipeline_phase_summary" "nvpn perf phase summary writer"
  assert_file_contains "$script" "assert_no_direct_fmp_runtime_artifacts" "nvpn perf no-direct runtime guard"
  assert_file_contains "$script" "decrypt_direct_fmp_endpoint_wait" "nvpn perf no-direct stage guard"
  assert_file_contains "$script" "NVPN_DOCKER_REQUIRE_NO_FSP_AEAD_HELPERS" "nvpn perf no-FSP-helper guard"
  assert_file_contains "$script" "assert_no_fsp_aead_helper_runtime_artifacts" "nvpn perf no-FSP-helper runtime guard"
  assert_file_contains "$script" "decrypt_fsp_path_helper" "nvpn perf FSP helper path guard"
  assert_file_contains "$script" "NVPN_DOCKER_EXPECT_FSP_OWNER_PLACEMENT" "nvpn perf FSP placement expectation guard"
  assert_file_contains "$script" "NVPN_DOCKER_PLACEMENT_PREFLIGHT" "nvpn perf FSP placement preflight guard"
  assert_file_contains "$script" 'NVPN_DOCKER_PLACEMENT_PREFLIGHT="$PLACEMENT_PREFLIGHT"' "nvpn perf exports effective placement preflight"
  assert_file_contains "$script" "NVPN_DOCKER_PLACEMENT_PREFLIGHT_PING_SIZE" "nvpn perf bulk-sized placement preflight"
  assert_file_contains "$script" "NVPN_DOCKER_PLACEMENT_PROFILE" "nvpn perf deterministic placement profile"
  assert_file_contains "$summary_lib" "FIPS_DECRYPT_FMP_SOURCE_AFFINE_SESSION_OWNER is retired" "nvpn perf retired source-affine env diagnostic"
  assert_file_contains "$summary_lib" "FIPS_DECRYPT_FSP_LOCAL_BULK_OPEN_WORKER is retired" "nvpn perf retired worker-open env diagnostic"
  assert_file_contains "$summary_lib" "FIPS_DECRYPT_FSP_AEAD_COMPLETION_BATCH_MAX is retired" "nvpn perf retired FSP completion batch env diagnostic"
  assert_file_contains "$summary_lib" "FIPS_LINUX_BULK_UDP_PACE_MBPS|FIPS_LINUX_BULK_UDP_PACE_BURST_BYTES" "nvpn perf retired Linux bulk pacer env names"
  assert_file_contains "$summary_lib" "Linux bulk UDP sends use the accepted unpaced" "nvpn perf retired Linux bulk pacer env diagnostic"
  assert_file_contains "$summary_lib" "FIPS_MACOS_ORDERED_SENDER|FIPS_MACOS_WORKER_STRIDE" "nvpn perf retired macOS sender env names"
  assert_file_contains "$script" "run_placement_preflight" "nvpn perf placement preflight before benchmark"
  assert_file_contains "$script" "node_b_fsp_owner_placement_load_line" "nvpn perf live placement classifier"
  assert_file_contains "$script" "nvpn-fsp-owner-placement.tsv" "nvpn perf FSP placement artifact"
  assert_file_contains "$script" "nvpn-iperf-socket-buffers.tsv" "nvpn perf iperf socket buffer artifact"
  assert_file_contains "$script" "nvpn-connected-udp-socket-buffers.tsv" "nvpn perf connected UDP socket buffer artifact"
  assert_file_contains "$script" "udp-receiver-limits.tsv" "nvpn perf UDP receiver limits artifact"
  assert_file_contains "$script" "net.core.rmem_max" "nvpn perf captures UDP receive buffer ceiling"
}

test_nvpn_perf_docker_placement_hunt_hooks() {
  local script="$ROOT_DIR/scripts/perf-docker-placement-hunt.sh"
  [[ -x "$script" ]] || fail "nvpn perf placement hunt script should be executable"
  assert_file_contains "$script" "NVPN_DOCKER_PLACEMENT_ATTEMPTS" "placement hunt attempt count env"
  assert_file_contains "$script" "NVPN_DOCKER_EXPECT_FSP_OWNER_PLACEMENT" "placement hunt expected placement env"
  assert_file_contains "$script" "NVPN_DOCKER_PLACEMENT_PREFLIGHT" "placement hunt preflight env"
  assert_file_contains "$script" "expected (exclusive )?node-b FSP owner placement" "placement hunt retries only placement misses"
  assert_file_contains "$script" "export NVPN_DOCKER_SKIP_BUILD=1" "placement hunt skips rebuild after first attempt"
  assert_file_contains "$script" "export NVPN_DOCKER_PLACEMENT_PREFLIGHT=1" "placement hunt enables cheap placement misses"
  assert_file_contains "$script" "success-output-dir.txt" "placement hunt success artifact"
}

test_nvpn_perf_docker_identity_hooks() {
  local script="$ROOT_DIR/scripts/perf-docker.sh"
  local summary_lib="$ROOT_DIR/scripts/lib-docker-bench-summary.sh"
  assert_file_contains "$script" "NVPN_DOCKER_NODE_A_NOSTR_SECRET_KEY" "node-a deterministic secret env"
  assert_file_contains "$script" "NVPN_DOCKER_NODE_A_NOSTR_PUBLIC_KEY" "node-a deterministic public env"
  assert_file_contains "$script" "NVPN_DOCKER_NODE_B_NOSTR_SECRET_KEY" "node-b deterministic secret env"
  assert_file_contains "$script" "NVPN_DOCKER_NODE_B_NOSTR_PUBLIC_KEY" "node-b deterministic public env"
  assert_file_contains "$script" "DEFAULT_NODE_A_NOSTR_SECRET_KEY" "node-a default Docker perf identity"
  assert_file_contains "$script" "DEFAULT_NODE_B_NOSTR_SECRET_KEY" "node-b default Docker perf identity"
  assert_file_contains "$script" "DEFAULT_NODE_A_ID" "node-a default Docker perf node-id"
  assert_file_contains "$script" "DEFAULT_NODE_B_ID" "node-b default Docker perf node-id"
  assert_file_contains "$script" "NVPN_DOCKER_NOSTR_IDENTITY_SOURCE" "effective identity source metadata"
  assert_file_contains "$script" "nvpn-runtime-identities.json" "runtime identity artifact"
  assert_file_contains "$script" "NVPN_DOCKER_NODE_A_ID" "node-a deterministic node-id env"
  assert_file_contains "$script" "NVPN_DOCKER_NODE_B_ID" "node-b deterministic node-id env"
  assert_file_contains "$script" "validate_nostr_identity_env" "deterministic identity validation hook"
  assert_file_contains "$script" "validate_node_id_env" "deterministic node-id validation hook"
  assert_file_contains "$script" "Docker Nostr identity env is all-or-none" "deterministic identity all-or-none guard"
  assert_file_contains "$script" "Docker node ID env is all-or-none" "deterministic node-id all-or-none guard"
  assert_file_contains "$script" "install_configured_nostr_identities" "deterministic identity install hook"
  assert_file_contains "$script" "install_configured_node_ids" "deterministic node-id install hook"
  assert_file_contains "$script" ".config.toml.nostr-secret-key.secret" "Linux sidecar secret install"
  assert_file_contains "$script" "stored-in-private-secret-file" "redacted config marker after identity install"
  assert_file_contains "$summary_lib" "runtime_identity" "runtime identity metadata"
  assert_file_contains "$summary_lib" "NVPN_DOCKER_NODE_A_RUNTIME_PUBLIC_KEY" "runtime public key metadata"
}

test_host_snapshot_artifact() {
  local dir path content
  dir="$(mktemp -d)"

  (
    PERF_OUTPUT_DIR="$dir"
    host_snapshot() {
      printf '%s\n' 'fixture host snapshot'
    }

    write_host_snapshot 'start'
    path="$dir/raw/host-start.txt"
    content="$(cat "$path")"
    assert_eq "$content" "fixture host snapshot" "host snapshot artifact"
  )

  rm -rf "$dir"
}

test_ping_parser_percentiles
test_ping_thresholds
test_iperf_parser_and_tcp_thresholds
test_iperf_progress_guard
test_iperf_interval_summary
test_iperf_sender_summary
test_iperf_timeout_configuration
test_iperf_probes_use_container_timeout
test_concurrent_iperf_timeout_is_reported
test_direct_underlay_policy
test_translated_nvpn_process_guard
test_pipeline_summary_collects_fips_and_nvpn_lines
test_pipeline_summary_prefers_peak_wait_lines
test_pipeline_summary_prefers_load_bearing_lines
test_pipeline_summary_scopes_selected_lines_after_start
test_docker_pipeline_range_helpers
test_pipeline_queue_wait_top_summary
test_pipeline_fmp_worker_batch_summary
test_pipeline_fmp_worker_dispatch_spread_summary
test_pipeline_fsp_owner_placement_summary
test_pipeline_decrypt_worker_batch_summary
test_pipeline_decrypt_worker_spread_summary
test_pipeline_decrypt_worker_turn_mix_summary
test_pipeline_linux_bulk_container_summary
test_pipeline_udp_send_batch_summary
test_pipeline_hard_event_summary
test_priority_hard_event_guard
test_priority_queue_wait_guard
test_rx_maintenance_priority_queue_wait_threshold
test_phase_argument_selection
test_phase_summary_pipeline_columns
test_start_compose_services_supports_skip_build
test_roaming_network_change_rebind_log_contract
test_roaming_network_change_probe_keeps_failure_budget_calibrated
test_dockerfile_supports_local_base_images
test_perf_harness_supports_cpu_stress
test_perf_metadata_maps_e2e_env
test_failure_summary_context
test_raw_artifact_helpers
test_selected_pipeline_summary_artifact
test_nvpn_perf_docker_phase_summary_hooks
test_nvpn_perf_docker_placement_hunt_hooks
test_nvpn_perf_docker_identity_hooks
test_host_snapshot_artifact

printf 'nvpn+FIPS perf harness self-test passed\n'
