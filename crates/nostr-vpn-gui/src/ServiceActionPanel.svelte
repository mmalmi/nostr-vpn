<script lang="ts">
  import {
    serviceLifecycleBadgeClass,
    serviceLifecycleBadgeText,
    serviceMetaText,
  } from './lib/app-view'
  import type { UiState } from './lib/types'

  export let state: UiState
  export let serviceSetupRequired = false
  export let serviceRepairPromptRecommended = false
  export let serviceRepairRetryAfterInstall = false
  export let serviceEnableRecommended = false
  export let serviceActionInFlight = false
  export let serviceActionStatus = ''
  export let onInstallSystemService: (connectAfter?: boolean) => Promise<void>
  export let onRepairSystemService: (connectAfter?: boolean) => Promise<void>
  export let onEnableSystemService: (connectAfter?: boolean) => Promise<void>
  export let onDisableSystemService: () => Promise<void>
  export let onUninstallSystemService: () => Promise<void>
</script>

<section
  class={`panel service-panel ${serviceSetupRequired || serviceRepairPromptRecommended ? 'service-panel-required' : ''}`}
  data-testid="service-panel"
>
  <div class="section-title-row">
    <div>
      <div class="panel-kicker">Action needed</div>
      <h2>Background Service</h2>
    </div>
    <div class="section-meta">{serviceMetaText(state)}</div>
  </div>

  <div class="row status-row">
    <span class={`badge ${state.serviceInstalled ? 'ok' : 'warn'}`}>
      {state.serviceInstalled ? 'Installed' : 'Setup required'}
    </span>
    <span class={`badge ${serviceLifecycleBadgeClass(state)}`}>
      {serviceLifecycleBadgeText(state)}
    </span>
    <span class="badge muted">Daemon {state.daemonRunning ? 'reachable' : 'idle'}</span>
  </div>

  <div class="service-panel-copy">
    <div class="service-panel-title">
      {serviceActionInFlight
        ? 'Updating the background service'
        : serviceRepairPromptRecommended
        ? 'Reinstall the service to finish this app update'
        : serviceSetupRequired
          ? 'Install once for reliable background VPN'
          : 'Enable the service to keep VPN control out of the GUI process'}
    </div>
    <div class="service-panel-text">
      {serviceActionInFlight
        ? 'Waiting for the service install or launchd restart to finish. This panel will update automatically when the new daemon is ready.'
        : serviceRepairPromptRecommended
        ? 'The running background service looks older than this app. Reinstall it once so the daemon matches the current version.'
        : 'Required for background startup, resilient reconnects, and avoiding repeated admin prompts.'}
    </div>
    {#if state.serviceStatusDetail}
      <div class="service-panel-detail" data-testid="service-status-detail">
        {state.serviceStatusDetail}
      </div>
    {/if}
    {#if serviceActionStatus}
      <div class="service-panel-detail service-panel-detail-ok">{serviceActionStatus}</div>
    {/if}
  </div>

  <div class="row service-actions-row">
    <button
      class={`btn ${serviceSetupRequired || serviceRepairPromptRecommended ? 'service-primary-btn' : ''}`}
      data-testid="install-service-btn"
      on:click={() =>
        serviceRepairPromptRecommended
          ? onRepairSystemService(serviceRepairRetryAfterInstall)
          : serviceEnableRecommended
            ? onEnableSystemService()
            : onInstallSystemService(serviceSetupRequired)}
      disabled={serviceActionInFlight}
    >
      {serviceRepairPromptRecommended
        ? serviceRepairRetryAfterInstall && !state.sessionActive
          ? 'Reinstall service and retry'
          : 'Reinstall service'
        : serviceEnableRecommended
          ? 'Enable service'
          : state.serviceInstalled
            ? 'Reinstall service'
            : 'Install service'}
    </button>
    {#if state.serviceEnablementSupported && state.serviceInstalled && !state.serviceDisabled}
      <button
        class="btn ghost"
        data-testid="disable-service-btn"
        on:click={onDisableSystemService}
        disabled={serviceActionInFlight}
      >
        Disable service
      </button>
    {/if}
    <button
      class="btn ghost"
      data-testid="uninstall-service-btn"
      on:click={onUninstallSystemService}
      disabled={!state.serviceInstalled || serviceActionInFlight}
    >
      Uninstall
    </button>
  </div>
</section>
