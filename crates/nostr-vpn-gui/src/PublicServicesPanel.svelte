<script lang="ts">
  import {
    formatTrafficBytes,
    formatTrafficRate,
    relayOperatorSummaryText,
    relaySessionTrafficText,
    short,
  } from './lib/app-view'
  import type { SettingsPatch, UiState } from './lib/types'

  export let state: UiState
  export let onUpdateSettings: (patch: SettingsPatch) => Promise<void>
</script>

<details class="panel collapsible-panel">
  <summary class="collapsible-summary">
    <div>
      <div class="panel-kicker">Contribute</div>
      <h2>Public Services</h2>
    </div>
    <div class="section-meta">
      {state.relayOperatorRunning || state.natAssistRunning
        ? 'Running'
        : state.relayForOthers || state.provideNatAssist
          ? 'Waiting to start'
          : 'Disabled'}
    </div>
  </summary>

  <div class="collapsible-body">
    <label class="toggle-row">
      <input
        type="checkbox"
        checked={state.relayForOthers}
        on:change={(event) =>
          onUpdateSettings({
            relayForOthers: (event.target as HTMLInputElement).checked,
          })}
      />
      <span>Relay traffic for others</span>
    </label>

    <label class="toggle-row">
      <input
        type="checkbox"
        checked={state.provideNatAssist}
        on:change={(event) =>
          onUpdateSettings({
            provideNatAssist: (event.target as HTMLInputElement).checked,
          })}
      />
      <span>Provide NAT assist</span>
    </label>

    <div class="config-path settings-note">{state.relayOperatorStatus}</div>
    <div class="config-path settings-note">{state.natAssistStatus}</div>
    <div class="config-path settings-note">{relayOperatorSummaryText(state)}</div>

    {#if state.relayOperator}
      <div class="stack rows">
        <div class="item-row">
          <div class="item-main">
            <div class="item-title">Relay identity</div>
            <div class="item-sub">{short(state.relayOperator.relayNpub, 18, 12)}</div>
          </div>
          <div class="participant-badges">
            <span class="badge muted">Relay operator</span>
          </div>
        </div>

        <div class="item-row">
          <div class="item-main">
            <div class="item-title">Advertised ingress</div>
            <div class="item-sub">
              {state.relayOperator.advertisedEndpoint || 'not advertising ingress'}
            </div>
          </div>
          <div class="participant-badges">
            <span class={`badge ${state.relayOperator.activeSessionCount > 0 ? 'warn' : 'muted'}`}>
              {formatTrafficRate(state.relayOperator.currentForwardBps)}
            </span>
          </div>
        </div>

        <div class="item-row">
          <div class="item-main">
            <div class="item-title">Lifetime totals</div>
            <div class="item-sub">
              {state.relayOperator.totalSessionsServed} sessions · {state.relayOperator.uniquePeerCount} peers · {formatTrafficBytes(state.relayOperator.totalForwardedBytes)}
            </div>
          </div>
        </div>
      </div>

      <div class="section-meta">Active relayed sessions</div>
      {#if state.relayOperator.activeSessions.length === 0}
        <div class="config-path settings-note">No peers are currently being relayed through this device.</div>
      {:else}
        <div class="stack rows">
          {#each state.relayOperator.activeSessions as session}
            <div class="item-row">
              <div class="item-main">
                <div class="item-title">
                  {short(session.requesterNpub, 16, 10)} → {short(session.targetNpub, 16, 10)}
                </div>
                <div class="item-sub">
                  {relaySessionTrafficText(session.bytesFromRequester, session.bytesFromTarget)} | started {session.startedText} | expires {session.expiresText}
                </div>
                <div class="item-sub">
                  ingress A {session.requesterIngressEndpoint} | ingress B {session.targetIngressEndpoint}
                </div>
              </div>
              <div class="participant-badges">
                <span class="badge warn">{formatTrafficBytes(session.totalForwardedBytes)}</span>
              </div>
            </div>
          {/each}
        </div>
      {/if}
    {:else}
      <div class="config-path settings-note">
        Run a local relay operator and its forwarded traffic, active sessions, and cumulative totals will appear here.
      </div>
    {/if}
  </div>
</details>
