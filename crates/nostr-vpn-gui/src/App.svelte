<script lang="ts">
  import { onDestroy, onMount } from 'svelte'
  import { invoke } from '@tauri-apps/api/core'
  import { listen } from '@tauri-apps/api/event'
  import jsQR from 'jsqr'
  import { Check, Copy, Trash2 } from 'lucide-svelte'
  import QRCode from 'qrcode'

  import { dispatchBootReady, waitForNextPaint } from './lib/boot.js'
  import {
    lanPairingDeadlineFromSnapshot,
    remainingSecsFromDeadline,
  } from './lib/countdown.js'
  import { heroStateText, heroStatusDetailText } from './lib/hero-state.js'
  import {
    buildInviteScanConstraintCandidates,
    openInviteScanStream,
  } from './lib/invite-scan.js'
  import {
    serviceRepairErrorText,
    serviceRepairRecommended,
    serviceRepairRetryRecommended,
  } from './lib/service-repair.js'
  import { parseAppDeepLink } from './lib/deep-link-actions.js'
  import { decodeInvitePayload, determineInviteImportTarget } from './lib/invite-code.js'
  import {
    canonicalizeMeshIdInput,
    formatMeshIdDraftForDisplay,
    formatMeshIdForDisplay,
    validateMeshIdInput,
  } from './lib/mesh-id.js'
  import { nodeNameDnsPreview } from './lib/node-name.js'
  import {
    activeNetwork,
    exitNodeAvailabilityClass,
    exitNodeAvailabilityText,
    exitNodeCandidates,
    filteredExitNodeCandidates,
    formatCountdown,
    formatTrafficBytes,
    formatTrafficRate,
    healthBadgeClass,
    healthSummaryText,
    heroBadgeText,
    heroDetailText,
    heroStateBadgeClass,
    heroSubtext,
    inactiveNetworks,
    networkAdminSummary,
    networkPeerSummary,
    offerExitNodeStatusText,
    onlineDeviceSummary,
    participantBadgeClass,
    participantPresenceBadgeText,
    participantTrafficText,
    participantTransportBadgeText,
    platformLabel,
    publicRelayFallbackStatusText,
    relayFallbackSummaryText,
    relayOperatorSummaryText,
    relaySessionTrafficText,
    routingModeStatusText,
    routingSectionMetaText,
    selectedExitNodeStatusText,
    serviceLifecycleBadgeClass,
    serviceLifecycleBadgeText,
    serviceMetaText,
    short,
  } from './lib/app-view'
  import SavedNetworksPanel from './SavedNetworksPanel.svelte'
  import {
    addAdmin,
    addNetwork,
    addParticipant,
    addRelay,
    acceptJoinRequest,
    connectSession,
    disableSystemService,
    disconnectSession,
    enableSystemService,
    importNetworkInvite,
    installCli,
    installSystemService,
    isAutostartEnabled,
    removeNetwork,
    removeAdmin,
    removeParticipant,
    removeRelay,
    renameNetwork,
    requestNetworkJoin,
    setNetworkEnabled,
    setNetworkJoinRequestsEnabled,
    setNetworkMeshId,
    setParticipantAlias,
    setAutostartEnabled,
    startLanPairing,
    stopLanPairing,
    tick,
    uninstallCli,
    uninstallSystemService,
    updateSettings,
  } from './lib/tauri'
  import InviteSharePanel from './InviteSharePanel.svelte'
  import type {
    HealthIssue,
    NetworkView,
    ParticipantView,
    PeerState,
    PresenceState,
    SettingsPatch,
    UiState,
  } from './lib/types'

  let state: UiState | null = null
  let relayInput = ''
  let error = ''
  let cliActionStatus = ''
  let serviceActionStatus = ''
  let copiedValue: 'pubkey' | 'meshId' | 'invite' | 'peerNpub' | null = null
  let copiedPeerNpub: string | null = null
  let inviteQrDataUrl = ''
  let inviteQrError = ''
  let inviteQrSource = ''
  let inviteQrSequence = 0

  let newNetworkName = ''
  let inviteInputDraft = ''
  let inviteImportHandle: number | null = null
  let inviteImportPendingValue = ''
  let inviteImportLastAttemptedValue = ''
  let inviteScanInput: HTMLInputElement | null = null
  let inviteScanVideo: HTMLVideoElement | null = null
  let inviteScanCanvas: HTMLCanvasElement | null = null
  let inviteScanStream: MediaStream | null = null
  let inviteScanOpen = false
  let inviteScanBusy = false
  let inviteScanStatus = ''
  let inviteScanError = ''
  let inviteScanFrameHandle: number | null = null
  let nodeNameDraft = ''
  let endpointDraft = ''
  let tunnelIpDraft = ''
  let listenPortDraft = ''
  let exitNodeDraft = ''
  let advertisedRoutesDraft = ''
  let magicDnsSuffixDraft = ''
  let exitNodeSearch = ''
  let draftsInitialized = false
  let showAdvancedRoutes = false

  let networkNameDrafts: Record<string, string> = {}
  let networkIdDrafts: Record<string, string> = {}
  let networkIdErrors: Record<string, string> = {}
  let participantInputDrafts: Record<string, string> = {}
  let participantAddAliasDrafts: Record<string, string> = {}
  let participantAliasDrafts: Record<string, string> = {}

  let autostartReady = false
  let autostartUpdating = false

  const debouncers = new Map<string, number>()
  let pollHandle: number | null = null
  let lanPairingTickHandle: number | null = null
  let copiedHandle: number | null = null
  let deepLinkUnlisten: (() => void) | null = null
  let refreshInFlight = false
  let actionInFlight = false
  let serviceInstallRecommended = false
  let serviceEnableRecommended = false
  let serviceRepairPromptRecommended = false
  let serviceRepairRetryAfterInstall = false
  let serviceRepairPromptShownFor = ''
  let serviceRepairPromptInFlight = false
  let serviceSetupRequired = false
  let vpnControlSupported = false
  let cliInstallSupported = false
  let startupSettingsSupported = false
  let trayBehaviorSupported = false
  let bootReadyDispatched = false
  let appDisposed = false
  let lanPairingDeadlineMs: number | null = null
  let lanPairingDisplayRemainingSecs = 0
  const processedDeepLinks = new Set<string>()

  const NETWORK_MESH_ID_IDLE_COMMIT_MS = 5000
  const nodeNamePreviewText = (nodeName: string, currentState: UiState) => {
    if (nodeName.trim() === currentState.nodeName.trim()) {
      return currentState.selfMagicDnsName
        ? `Shared as ${currentState.selfMagicDnsName}`
        : 'Shared name has no DNS-safe .nvpn label yet.'
    }

    const preview = nodeNameDnsPreview(nodeName, currentState.magicDnsSuffix)
    return preview ? `Will share as ${preview}` : 'Shared name has no DNS-safe .nvpn label yet.'
  }

  $: serviceInstallRecommended = !!state?.serviceSupported && !state.serviceInstalled
  $: serviceEnableRecommended =
    !!state?.serviceEnablementSupported && !!state?.serviceInstalled && !!state?.serviceDisabled
  $: serviceRepairPromptRecommended = serviceRepairRecommended(error, state)
  $: serviceRepairRetryAfterInstall = serviceRepairRetryRecommended(error)
  $: serviceSetupRequired = serviceInstallRecommended && !state?.daemonRunning
  $: vpnControlSupported = !!state?.vpnSessionControlSupported
  $: cliInstallSupported = !!state?.cliInstallSupported
  $: startupSettingsSupported = !!state?.startupSettingsSupported
  $: trayBehaviorSupported = !!state?.trayBehaviorSupported
  $: {
    const invite = state?.activeNetworkInvite ?? ''
    if (invite !== inviteQrSource) {
      inviteQrSource = invite
      void refreshInviteQr(invite)
    }
  }
  $: if (
    state &&
    serviceRepairPromptRecommended &&
    !actionInFlight &&
    !refreshInFlight &&
    !serviceRepairPromptInFlight &&
    !appDisposed
  ) {
    void maybePromptForServiceRepair()
  }

  async function refreshInviteQr(invite: string) {
    const sequence = ++inviteQrSequence
    if (!invite) {
      inviteQrDataUrl = ''
      inviteQrError = ''
      return
    }

    try {
      const dataUrl = await QRCode.toDataURL(invite, {
        errorCorrectionLevel: 'M',
        margin: 1,
        scale: 8,
        color: {
          dark: '#121926',
          light: '#ffffff',
        },
      })
      if (sequence === inviteQrSequence) {
        inviteQrDataUrl = dataUrl
        inviteQrError = ''
      }
    } catch {
      if (sequence === inviteQrSequence) {
        inviteQrDataUrl = ''
        inviteQrError = 'Invite QR unavailable'
      }
    }
  }

  const describeInviteScanError = (err: unknown) => {
    const name =
      err && typeof err === 'object' && 'name' in err ? String((err as { name?: unknown }).name) : ''
    switch (name) {
      case 'NotAllowedError':
      case 'PermissionDeniedError':
        return 'Camera access was denied. You can still scan a saved QR image.'
      case 'NotFoundError':
      case 'DevicesNotFoundError':
        return 'No camera was found. You can still scan a saved QR image.'
      case 'NotReadableError':
      case 'TrackStartError':
        return 'The camera is busy in another app. Close it there or scan a saved QR image.'
      default:
        return `Live QR scanning failed: ${String(err)}`
    }
  }

  const ensureInviteScanCanvas = () => {
    if (!inviteScanCanvas) {
      inviteScanCanvas = document.createElement('canvas')
    }
    return inviteScanCanvas
  }

  const decodeInviteFromImageSource = (
    source: CanvasImageSource,
    width: number,
    height: number,
  ) => {
    if (!width || !height) {
      return null
    }

    const canvas = ensureInviteScanCanvas()
    canvas.width = width
    canvas.height = height
    const context = canvas.getContext('2d', { willReadFrequently: true })
    if (!context) {
      throw new Error('QR scanner could not read image pixels')
    }

    context.drawImage(source, 0, 0, width, height)
    const imageData = context.getImageData(0, 0, width, height)
    return jsQR(imageData.data, width, height, {
      inversionAttempts: 'attemptBoth',
    })?.data?.trim() || null
  }

  const decodeInviteFromFile = async (file: File) => {
    const objectUrl = URL.createObjectURL(file)
    try {
      const image = await new Promise<HTMLImageElement>((resolve, reject) => {
        const next = new Image()
        next.onload = () => resolve(next)
        next.onerror = () => reject(new Error('Could not read the selected image'))
        next.src = objectUrl
      })
      const invite = decodeInviteFromImageSource(
        image,
        image.naturalWidth || image.width,
        image.naturalHeight || image.height,
      )
      if (!invite) {
        throw new Error('No QR code was found in the selected image')
      }
      return invite
    } finally {
      URL.revokeObjectURL(objectUrl)
    }
  }

  const stopInviteScan = () => {
    if (inviteScanFrameHandle !== null) {
      window.cancelAnimationFrame(inviteScanFrameHandle)
      inviteScanFrameHandle = null
    }
    if (inviteScanStream) {
      for (const track of inviteScanStream.getTracks()) {
        track.stop()
      }
      inviteScanStream = null
    }
    if (inviteScanVideo) {
      inviteScanVideo.pause()
      inviteScanVideo.srcObject = null
    }
    inviteScanBusy = false
    inviteScanOpen = false
  }

  const queueInviteScanFrame = () => {
    if (!inviteScanOpen) {
      return
    }

    inviteScanFrameHandle = window.requestAnimationFrame(() => {
      inviteScanFrameHandle = null
      void scanInviteVideoFrame()
    })
  }

  const buildInviteImportPrompt = (invite: {
    networkName: string
    networkId: string
    inviterNpub: string
  }) => {
    const lines = [
      `Import invite for "${invite.networkName}" from ${short(invite.inviterNpub, 18, 12)}?`,
    ]

    if (state) {
      const importTarget = determineInviteImportTarget(
        state.networks,
        activeNetwork(state).id,
        invite.networkId,
      )
      switch (importTarget.mode) {
        case 'existing':
          lines.push('This adds the scanned device to the matching network you already have.')
          break
        case 'reuse-active':
          lines.push('This reuses your current empty network slot and fills it from the invite.')
          break
        case 'create':
        default:
          lines.push('This creates a new network entry so your current network stays untouched.')
          break
      }
    }

    lines.push('Press Cancel to fill the invite field instead of importing right away.')
    return lines.join('\n\n')
  }

  type InviteImportOptions = {
    updateDraft?: boolean
    clearDraftOnSuccess?: boolean
    autoConnectOnSuccess?: boolean
  }

  const importInviteCode = async (invite: string, options: InviteImportOptions = {}) => {
    const normalized = invite.trim()
    if (!normalized) {
      return false
    }

    if (options.updateDraft) {
      inviteInputDraft = normalized
    }

    await runAction(() => importNetworkInvite(normalized))
    const succeeded = !error
    if (succeeded && options.autoConnectOnSuccess) {
      await ensureSessionActiveAfterInviteImport()
    }
    if (succeeded && options.clearDraftOnSuccess) {
      inviteInputDraft = ''
      inviteImportLastAttemptedValue = ''
    }
    return succeeded
  }

  const clearInviteImportDebounce = () => {
    if (inviteImportHandle !== null) {
      window.clearTimeout(inviteImportHandle)
      inviteImportHandle = null
    }
  }

  const scheduleInviteImportAttempt = (invite: string) => {
    const normalized = invite.trim()
    inviteImportPendingValue = normalized
    clearInviteImportDebounce()

    if (!normalized) {
      inviteImportLastAttemptedValue = ''
      return
    }

    inviteImportHandle = window.setTimeout(async () => {
      inviteImportHandle = null
      if (actionInFlight) {
        scheduleInviteImportAttempt(inviteImportPendingValue)
        return
      }

      const pending = inviteImportPendingValue.trim()
      if (!pending || pending === inviteImportLastAttemptedValue) {
        return
      }

      inviteImportLastAttemptedValue = pending
      await importInviteCode(pending, {
        updateDraft: true,
        clearDraftOnSuccess: true,
        autoConnectOnSuccess: true,
      })
    }, 250)
  }

  async function ensureSessionActiveAfterInviteImport() {
    if (!state || !state.vpnSessionControlSupported || state.sessionActive) {
      return
    }

    if (serviceSetupRequired) {
      await onInstallSystemService(true)
      return
    }

    if (serviceEnableRecommended) {
      await onEnableSystemService(true)
      return
    }

    await runAction(connectSession)
  }

  const handleScannedInvite = async (invite: string) => {
    const normalized = invite.trim()
    let parsed
    try {
      parsed = decodeInvitePayload(normalized)
    } catch (err) {
      throw new Error(`Scanned QR is not a valid Nostr VPN invite: ${String(err)}`)
    }

    inviteScanError = ''
    inviteScanStatus = ''

    if (typeof window.confirm === 'function' && !window.confirm(buildInviteImportPrompt(parsed))) {
      inviteInputDraft = normalized
      inviteScanStatus = 'Invite loaded into the field.'
      return
    }

    const imported = await importInviteCode(normalized, {
      updateDraft: true,
      clearDraftOnSuccess: true,
      autoConnectOnSuccess: true,
    })
    if (imported) {
      inviteScanStatus = `Imported ${parsed.networkName}.`
    }
  }

  async function scanInviteVideoFrame() {
    if (!inviteScanOpen || !inviteScanVideo) {
      return
    }

    if (
      inviteScanVideo.readyState < HTMLMediaElement.HAVE_CURRENT_DATA ||
      inviteScanVideo.videoWidth === 0 ||
      inviteScanVideo.videoHeight === 0
    ) {
      queueInviteScanFrame()
      return
    }

    const invite = decodeInviteFromImageSource(
      inviteScanVideo,
      inviteScanVideo.videoWidth,
      inviteScanVideo.videoHeight,
    )
    if (!invite) {
      queueInviteScanFrame()
      return
    }

    stopInviteScan()
    try {
      await handleScannedInvite(invite)
    } catch (err) {
      inviteScanError = String(err)
    }
  }

  async function onStartInviteScan() {
    if (!navigator.mediaDevices?.getUserMedia) {
      inviteScanError = 'Live QR scanning is unavailable here. Use Choose Image instead.'
      return
    }

    stopInviteScan()
    inviteScanError = ''
    inviteScanStatus = 'Requesting camera access...'
    inviteScanOpen = true
    await waitForNextPaint(window)

    if (!inviteScanVideo) {
      inviteScanOpen = false
      inviteScanStatus = ''
      inviteScanError = 'Scanner preview could not open'
      return
    }

    try {
      const cameraCandidates = buildInviteScanConstraintCandidates({
        mobile: Boolean(state?.mobile),
      })
      inviteScanStream = await openInviteScanStream(
        navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices),
        cameraCandidates,
      )
      inviteScanVideo.srcObject = inviteScanStream
      await inviteScanVideo.play()
      inviteScanBusy = true
      inviteScanStatus = 'Point the camera at an invite QR code.'
      queueInviteScanFrame()
    } catch (err) {
      stopInviteScan()
      inviteScanStatus = ''
      inviteScanError = describeInviteScanError(err)
    }
  }

  function onCloseInviteScan() {
    stopInviteScan()
    inviteScanStatus = ''
  }

  function onChooseInviteQrImage() {
    stopInviteScan()
    inviteScanError = ''
    inviteScanStatus = ''
    inviteScanInput?.click()
  }

  async function onInviteScanFileSelected(event: Event) {
    const input = event.currentTarget as HTMLInputElement
    const file = input.files?.[0]
    input.value = ''
    if (!file) {
      return
    }

    inviteScanError = ''
    inviteScanStatus = 'Scanning QR image...'
    try {
      const invite = await decodeInviteFromFile(file)
      await handleScannedInvite(invite)
    } catch (err) {
      inviteScanStatus = ''
      inviteScanError = String(err)
    }
  }

  function syncLanPairingCountdown() {
    const now = Date.now()
    lanPairingDeadlineMs = lanPairingDeadlineFromSnapshot(
      lanPairingDeadlineMs,
      !!state?.lanPairingActive,
      state?.lanPairingRemainingSecs ?? 0,
      now,
    )
    lanPairingDisplayRemainingSecs = remainingSecsFromDeadline(lanPairingDeadlineMs, now)
  }

  function tickLanPairingCountdown() {
    lanPairingDisplayRemainingSecs = remainingSecsFromDeadline(lanPairingDeadlineMs, Date.now())
  }

  $: if (state) {
    syncLanPairingCountdown()
  } else {
    lanPairingDeadlineMs = null
    lanPairingDisplayRemainingSecs = 0
  }

  async function refresh() {
    if (refreshInFlight || actionInFlight) {
      return
    }
    refreshInFlight = true
    try {
      state = await tick()
      initializeDraftsOnce()
      syncDraftsFromState()
    } catch (err) {
      error = String(err)
    } finally {
      refreshInFlight = false
    }
  }

  function currentServiceRepairPromptKey(currentState: UiState) {
    return `${currentState.appVersion}:${
      currentState.serviceBinaryVersion || currentState.daemonBinaryVersion || 'unknown'
    }`
  }

  async function maybePromptForServiceRepair() {
    if (
      !state ||
      !serviceRepairRecommended(error, state) ||
      serviceRepairPromptInFlight ||
      actionInFlight ||
      refreshInFlight
    ) {
      return
    }

    const promptKey = currentServiceRepairPromptKey(state)
    if (serviceRepairPromptShownFor === promptKey) {
      return
    }
    serviceRepairPromptShownFor = promptKey

    if (typeof window.confirm !== 'function') {
      return
    }

    serviceRepairPromptInFlight = true
    try {
      if (
        window.confirm(
          'Background service is out of date. Reinstall it now so this app version can control the VPN?'
        )
      ) {
        await onRepairSystemService(false)
      }
    } finally {
      serviceRepairPromptInFlight = false
    }
  }

  async function ensureStateLoaded() {
    if (!state) {
      await refresh()
    }
    return state
  }

  async function handleAppDeepLink(url: string) {
    const normalized = url.trim()
    if (!normalized || processedDeepLinks.has(normalized)) {
      return
    }
    processedDeepLinks.add(normalized)

    const action = parseAppDeepLink(normalized)
    if (!action) {
      return
    }

    if (action.type === 'invite') {
      await runAction(() => importNetworkInvite(action.invite))
      return
    }

    if (action.type === 'tick') {
      await refresh()
      return
    }

    const current = await ensureStateLoaded()
    const network = current ? activeNetwork(current) : null
    if (!network) {
      return
    }

    if (action.type === 'request-join') {
      await runAction(() => requestNetworkJoin(network.id))
      return
    }

    await runAction(() => acceptJoinRequest(network.id, action.requesterNpub))
  }

  async function initializeDeepLinkHandling() {
    if (typeof window === 'undefined' || !('__TAURI_INTERNALS__' in window)) {
      return
    }

    try {
      deepLinkUnlisten = await listen('deep-link://new-url', async (event) => {
        const urls = Array.isArray(event.payload) ? event.payload : []
        for (const url of urls) {
          if (typeof url === 'string') {
            await handleAppDeepLink(url)
          }
        }
      })

      const current = await invoke<string[] | null>('plugin:deep-link|get_current')
      if (!Array.isArray(current)) {
        return
      }
      for (const url of current) {
        if (typeof url === 'string') {
          await handleAppDeepLink(url)
        }
      }
    } catch (err) {
      console.error('Failed to initialize deep-link handling', err)
    }
  }

  function markBootReady() {
    if (bootReadyDispatched) {
      return
    }

    bootReadyDispatched = true
    dispatchBootReady(window)
  }

  function initializeDraftsOnce() {
    if (!state || draftsInitialized) {
      return
    }

    nodeNameDraft = state.nodeName
    endpointDraft = state.endpoint
    tunnelIpDraft = state.tunnelIp
    listenPortDraft = String(state.listenPort)
    exitNodeDraft = state.exitNode
    advertisedRoutesDraft = state.advertisedRoutes.join(', ')
    magicDnsSuffixDraft = state.magicDnsSuffix
    draftsInitialized = true
    syncDraftsFromState()
  }

  function syncDraftsFromState() {
    if (!state) {
      networkNameDrafts = {}
      networkIdDrafts = {}
      networkIdErrors = {}
      participantAliasDrafts = {}
      return
    }

    const nextNetworkNames: Record<string, string> = {}
    const nextNetworkIds: Record<string, string> = {}
    const nextParticipantInput: Record<string, string> = {}
    const nextParticipantAddAlias: Record<string, string> = {}
    const nextParticipantAliases: Record<string, string> = {}

    for (const network of state.networks) {
      const nameDebounceKey = `network-name-${network.id}`
      const meshIdDebounceKey = `network-id-${network.id}`
      nextNetworkNames[network.id] = debouncers.has(nameDebounceKey)
        ? (networkNameDrafts[network.id] ?? network.name)
        : network.name
      nextNetworkIds[network.id] = debouncers.has(meshIdDebounceKey) || !!networkIdErrors[network.id]
        ? (networkIdDrafts[network.id] ?? formatMeshIdForDisplay(network.networkId))
        : formatMeshIdForDisplay(network.networkId)

      nextParticipantInput[network.id] = participantInputDrafts[network.id] ?? ''
      nextParticipantAddAlias[network.id] = participantAddAliasDrafts[network.id] ?? ''

      for (const participant of network.participants) {
        const aliasDebounceKey = `alias-${participant.pubkeyHex}`
        nextParticipantAliases[participant.pubkeyHex] = debouncers.has(aliasDebounceKey)
          ? (participantAliasDrafts[participant.pubkeyHex] ?? participant.magicDnsAlias)
          : participant.magicDnsAlias
      }
    }

    networkNameDrafts = nextNetworkNames
    networkIdDrafts = nextNetworkIds
    participantInputDrafts = nextParticipantInput
    participantAddAliasDrafts = nextParticipantAddAlias
    participantAliasDrafts = nextParticipantAliases

    if (!debouncers.has('magicDnsSuffix')) {
      magicDnsSuffixDraft = state.magicDnsSuffix
    }
    exitNodeDraft = state.exitNode
    if (state.advertisedRoutes.length > 0) {
      showAdvancedRoutes = true
    }
    if (!debouncers.has('advertisedRoutes')) {
      advertisedRoutesDraft = state.advertisedRoutes.join(', ')
    }
  }

  function clearDebounce(key: string) {
    const existing = debouncers.get(key)
    if (existing) {
      window.clearTimeout(existing)
      debouncers.delete(key)
    }
  }

  function debounce(key: string, fn: () => Promise<void>, delay = 450) {
    clearDebounce(key)

    const timer = window.setTimeout(async () => {
      debouncers.delete(key)
      await fn()
    }, delay)

    debouncers.set(key, timer)
  }

  function networkMeshIdDebounceKey(networkId: string) {
    return `network-id-${networkId}`
  }

  function currentNetworkMeshId(networkId: string) {
    return state?.networks.find((network) => network.id === networkId)?.networkId ?? null
  }

  function setNetworkMeshIdError(networkId: string, message: string) {
    if (message) {
      networkIdErrors = {
        ...networkIdErrors,
        [networkId]: message,
      }
      return
    }

    if (!(networkId in networkIdErrors)) {
      return
    }

    const nextErrors = { ...networkIdErrors }
    delete nextErrors[networkId]
    networkIdErrors = nextErrors
  }

  function meshIdDraftError(networkId: string) {
    return networkIdErrors[networkId] ?? ''
  }

  function meshIdHelperText(networkId: string, currentMeshId: string) {
    const errorMessage = meshIdDraftError(networkId)
    if (errorMessage) {
      return errorMessage
    }
    return 'Best for new IDs: letters or numbers in 4-character groups, like abcd-efgh-ijkl.'
  }

  async function commitNetworkMeshId(networkId: string, value: string) {
    const debounceKey = networkMeshIdDebounceKey(networkId)
    clearDebounce(debounceKey)

    const currentMeshId = currentNetworkMeshId(networkId)
    if (!currentMeshId) {
      return
    }

    const trimmed = value.trim()
    if (!trimmed) {
      setNetworkMeshIdError(networkId, '')
      networkIdDrafts = {
        ...networkIdDrafts,
        [networkId]: formatMeshIdForDisplay(currentMeshId),
      }
      return
    }

    const validationError = validateMeshIdInput(trimmed, currentMeshId)
    if (validationError) {
      setNetworkMeshIdError(networkId, validationError)
      return
    }

    const normalized = canonicalizeMeshIdInput(trimmed, currentMeshId)
    if (normalized === currentMeshId) {
      setNetworkMeshIdError(networkId, '')
      networkIdDrafts = {
        ...networkIdDrafts,
        [networkId]: formatMeshIdForDisplay(currentMeshId),
      }
      return
    }

    setNetworkMeshIdError(networkId, '')
    await runAction(() => setNetworkMeshId(networkId, normalized))
  }

  async function runAction(action: () => Promise<UiState>) {
    if (actionInFlight) {
      return
    }
    actionInFlight = true
    try {
      state = await action()
      error = ''
      initializeDraftsOnce()
      syncDraftsFromState()
    } catch (err) {
      error = String(err)
      cliActionStatus = ''
      serviceActionStatus = ''
      try {
        state = await tick()
        initializeDraftsOnce()
        syncDraftsFromState()
      } catch {
        // Keep the original action error if state refresh also fails.
      }
    } finally {
      actionInFlight = false
    }
  }

  async function onToggleSession() {
    if (!state) {
      return
    }

    if (serviceSetupRequired && !state.sessionActive) {
      await onInstallSystemService(true)
      return
    }

    if (serviceEnableRecommended && !state.sessionActive) {
      await onEnableSystemService(true)
      return
    }

    await runAction(state.sessionActive ? disconnectSession : connectSession)
  }

  async function onInstallCli() {
    await runAction(installCli)
    if (!error) {
      cliActionStatus = 'CLI installed in PATH (/usr/local/bin/nvpn)'
    }
  }

  async function onUninstallCli() {
    await runAction(uninstallCli)
    if (!error) {
      cliActionStatus = 'CLI removed from PATH (/usr/local/bin/nvpn)'
    }
  }

  async function onInstallSystemService(connectAfter = false) {
    const wasInstalled = !!state?.serviceInstalled
    await runAction(installSystemService)
    if (!error) {
      serviceActionStatus = wasInstalled
        ? 'System service reinstalled and started'
        : 'System service installed and started'
    } else if (!wasInstalled && state?.serviceInstalled) {
      error = ''
      serviceActionStatus = state.serviceRunning
        ? 'System service installed and started'
        : 'System service installed'
    }
    if (connectAfter && !error && state && !state.sessionActive) {
      await runAction(connectSession)
      if (!error) {
        serviceActionStatus = state.sessionActive
          ? wasInstalled
            ? 'System service reinstalled and VPN started'
            : 'System service installed and VPN started'
          : wasInstalled
            ? 'System service reinstalled'
            : 'System service installed'
      }
    }
  }

  async function onRepairSystemService(connectAfter = false) {
    await onInstallSystemService(connectAfter)
  }

  async function onEnableSystemService(connectAfter = false) {
    const wasDisabled = !!state?.serviceDisabled
    await runAction(enableSystemService)
    if (!error) {
      serviceActionStatus = 'System service enabled and started'
    } else if (wasDisabled && state && !state.serviceDisabled) {
      error = ''
      serviceActionStatus = state.serviceRunning
        ? 'System service enabled and started'
        : 'System service enabled'
    }
    if (connectAfter && !error && state && !state.sessionActive) {
      await runAction(connectSession)
    }
  }

  async function onDisableSystemService() {
    const wasEnabled = !!state?.serviceInstalled && !state?.serviceDisabled
    await runAction(disableSystemService)
    if (!error) {
      serviceActionStatus = 'System service disabled'
    } else if (wasEnabled && state?.serviceDisabled) {
      error = ''
      serviceActionStatus = 'System service disabled'
    }
  }

  async function onUninstallSystemService() {
    const wasInstalled = !!state?.serviceInstalled
    await runAction(uninstallSystemService)
    if (!error) {
      serviceActionStatus = 'System service removed'
    } else if (wasInstalled && state && !state.serviceInstalled) {
      error = ''
      serviceActionStatus = 'System service removed'
    }
  }

  async function onAddNetwork() {
    const name = newNetworkName.trim()
    await runAction(() => addNetwork(name))
    newNetworkName = ''
  }

  function onNetworkNameInput(networkId: string, value: string) {
    networkNameDrafts = {
      ...networkNameDrafts,
      [networkId]: value,
    }

    debounce(`network-name-${networkId}`, async () => {
      await runAction(() => renameNetwork(networkId, value))
    }, 500)
  }

  function onNetworkMeshIdInput(networkId: string, value: string) {
    networkIdDrafts = {
      ...networkIdDrafts,
      [networkId]: value,
    }

    const currentMeshId = currentNetworkMeshId(networkId)
    if (!currentMeshId) {
      return
    }

    const normalized = value.trim()
    const debounceKey = networkMeshIdDebounceKey(networkId)
    const validationError = validateMeshIdInput(normalized, currentMeshId)
    setNetworkMeshIdError(networkId, validationError)

    if (validationError) {
      clearDebounce(debounceKey)
      return
    }

    const canonical = canonicalizeMeshIdInput(normalized, currentMeshId)
    if (!canonical || canonical === currentMeshId) {
      clearDebounce(debounceKey)
      return
    }

    debounce(debounceKey, () => commitNetworkMeshId(networkId, value), NETWORK_MESH_ID_IDLE_COMMIT_MS)
  }

  async function onAddParticipant(networkId: string) {
    const npub = participantInputDrafts[networkId]?.trim() || ''
    const alias = participantAddAliasDrafts[networkId]?.trim() || ''
    if (!npub) {
      return
    }

    await runAction(() => addParticipant(networkId, npub, alias))
    participantInputDrafts = {
      ...participantInputDrafts,
      [networkId]: '',
    }
    participantAddAliasDrafts = {
      ...participantAddAliasDrafts,
      [networkId]: '',
    }
  }

  async function onToggleAdmin(networkId: string, participant: ParticipantView) {
    if (participant.isAdmin) {
      await runAction(() => removeAdmin(networkId, participant.npub))
      return
    }
    await runAction(() => addAdmin(networkId, participant.npub))
  }

  async function onJoinLanPeer(invite: string) {
    await importInviteCode(invite)
  }

  async function onRequestNetworkJoin(networkId: string) {
    await runAction(() => requestNetworkJoin(networkId))
  }

  async function onAcceptJoinRequest(networkId: string, requesterNpub: string) {
    await runAction(() => acceptJoinRequest(networkId, requesterNpub))
  }

  async function onToggleJoinRequests(networkId: string, enabled: boolean) {
    await runAction(() => setNetworkJoinRequestsEnabled(networkId, enabled))
  }

  async function onStartLanPairing() {
    await runAction(() => startLanPairing())
  }

  async function onStopLanPairing() {
    await runAction(() => stopLanPairing())
  }

  async function onImportInvite() {
    await importInviteCode(inviteInputDraft, {
      updateDraft: true,
      clearDraftOnSuccess: true,
      autoConnectOnSuccess: true,
    })
  }

  function onInviteInput(event: Event) {
    const value = (event.currentTarget as HTMLInputElement).value
    inviteInputDraft = value
    error = ''
    scheduleInviteImportAttempt(value)
  }

  function onInvitePaste(event: ClipboardEvent) {
    const pasted = event.clipboardData?.getData('text/plain') ?? ''
    if (!pasted) {
      return
    }

    event.preventDefault()
    inviteInputDraft = pasted.trim()
    error = ''
    scheduleInviteImportAttempt(inviteInputDraft)
  }

  async function onAddRelay() {
    const relay = relayInput.trim()
    if (!relay) {
      return
    }

    await runAction(() => addRelay(relay))
    relayInput = ''
  }

  async function onUpdateSettings(patch: SettingsPatch) {
    await runAction(() => updateSettings(patch))
  }

  async function onSelectExitNode(npub: string) {
    exitNodeDraft = npub
    await onUpdateSettings({ exitNode: npub })
  }

  function onParticipantAliasInput(
    participantNpub: string,
    participantHex: string,
    value: string,
  ) {
    participantAliasDrafts = {
      ...participantAliasDrafts,
      [participantHex]: value,
    }

    debounce(
      `alias-${participantHex}`,
      async () => {
        await runAction(() => setParticipantAlias(participantNpub, value))
      },
      500,
    )
  }

  async function refreshAutostart() {
    if (!state) {
      autostartReady = true
      return
    }

    if (!state.startupSettingsSupported) {
      autostartReady = true
      return
    }

    const runtimeEnabled = await isAutostartEnabled()
    if (runtimeEnabled !== state.launchOnStartup) {
      const ok = await setAutostartEnabled(state.launchOnStartup)
      // Startup sync can run in environments where autostart cannot be managed
      // (for example the Linux Tauri-driver container), so avoid surfacing a
      // boot-time banner unless the user explicitly changed the setting.
      if (!ok) {
        autostartReady = true
        return
      }
    }

    autostartReady = true
  }

  async function onToggleAutostart(enabled: boolean) {
    if (!state || !state.startupSettingsSupported) {
      return
    }

    const previous = state.launchOnStartup
    autostartUpdating = true
    await onUpdateSettings({ launchOnStartup: enabled })
    const ok = await setAutostartEnabled(enabled)

    if (!ok) {
      error = 'Failed to update autostart setting'
      await onUpdateSettings({ launchOnStartup: previous })
    } else {
      await refreshAutostart()
    }

    autostartUpdating = false
  }

  async function copyText(
    value: string,
    kind: 'pubkey' | 'meshId' | 'invite' | 'peerNpub',
    peerNpub: string | null = null,
  ) {
    try {
      await navigator.clipboard.writeText(value)
      copiedValue = kind
      copiedPeerNpub = kind === 'peerNpub' ? (peerNpub ?? value) : null
      if (copiedHandle) {
        window.clearTimeout(copiedHandle)
      }
      copiedHandle = window.setTimeout(() => {
        copiedValue = null
        copiedPeerNpub = null
        copiedHandle = null
      }, 2000)
    } catch {
      error = 'Clipboard copy failed'
    }
  }

  async function copyPubkey() {
    if (!state) {
      return
    }

    await copyText(state.ownNpub, 'pubkey')
  }

  async function copyPeerNpub(npub: string) {
    await copyText(npub, 'peerNpub', npub)
  }

  async function copyMeshId() {
    if (!state) {
      return
    }

    const network = activeNetwork(state)
    const draftMeshId = networkIdDrafts[network.id] ?? formatMeshIdForDisplay(network.networkId)
    const rawMeshId = meshIdDraftError(network.id)
      ? network.networkId
      : canonicalizeMeshIdInput(draftMeshId, network.networkId)
    await copyText(rawMeshId, 'meshId')
  }

  async function copyInvite() {
    if (!state?.activeNetworkInvite) {
      return
    }

    await copyText(state.activeNetworkInvite, 'invite')
  }

  onMount(() => {
    lanPairingTickHandle = window.setInterval(tickLanPairingCountdown, 1000)

    void (async () => {
      await waitForNextPaint(window)
      if (appDisposed) {
        return
      }

      await refresh()
      if (appDisposed) {
        return
      }

      await initializeDeepLinkHandling()
      if (appDisposed) {
        return
      }

      markBootReady()
      await refreshAutostart()
      if (appDisposed) {
        return
      }

      pollHandle = window.setInterval(refresh, 1500)
    })()
  })

  onDestroy(() => {
    appDisposed = true
    clearInviteImportDebounce()
    stopInviteScan()
    if (pollHandle) {
      window.clearInterval(pollHandle)
    }
    if (lanPairingTickHandle) {
      window.clearInterval(lanPairingTickHandle)
    }
    if (copiedHandle) {
      window.clearTimeout(copiedHandle)
    }
    if (deepLinkUnlisten) {
      deepLinkUnlisten()
    }
    for (const timer of debouncers.values()) {
      window.clearTimeout(timer)
    }
  })
</script>

<main class="app-shell">
  <div class="drag-padding drag-padding-top" data-tauri-drag-region aria-hidden="true"></div>
  <div class="drag-padding drag-padding-left" data-tauri-drag-region aria-hidden="true"></div>
  <div class="drag-padding drag-padding-right" data-tauri-drag-region aria-hidden="true"></div>
  <div class="drag-padding drag-padding-bottom" data-tauri-drag-region aria-hidden="true"></div>

  <header class="window-chrome" data-tauri-drag-region>
    <div class="window-title" data-testid="window-title">Nostr VPN</div>
  </header>

  <section class="identity-card panel hero-card">
    {#if state}
      {@const activeNetworkView = activeNetwork(state)}
      <div class="row hero-row">
        <div class="hero-copy">
          <div class="panel-kicker">Status</div>
          <div class="row hero-title-row">
            <h1 data-testid="active-network-title">{activeNetworkView.name}</h1>
            {#if activeNetworkView.localIsAdmin}
              <span class="badge ok" data-testid="active-network-admin-badge">Admin</span>
            {/if}
            <span class={`badge ${heroStateBadgeClass(state)}`}>
              {heroBadgeText(state)}
            </span>
          </div>
          <div class="hero-subtitle">{heroSubtext(state)}</div>
        </div>
        {#if vpnControlSupported && !serviceSetupRequired}
          <button
            class={`session-switch ${state.sessionActive ? 'on' : 'off'}`}
            role="switch"
            aria-checked={state.sessionActive}
            aria-label="Toggle VPN session"
            data-testid="session-toggle"
            on:click={onToggleSession}
          >
            <span class="session-switch-track" aria-hidden="true">
              <span class="session-switch-thumb"></span>
            </span>
            <span class="session-switch-label">VPN {state.sessionActive ? 'On' : 'Off'}</span>
          </button>
        {/if}
      </div>

      <div class="hero-stats-grid">
        <div class="hero-stat-card" data-testid="hero-identity-card">
          <div class="panel-kicker">Identity</div>
          <div class="hero-identity-row">
            <div class="copy-value hero-copy-value" data-testid="pubkey">
              {state.ownNpub}
            </div>
            <button
              class="btn icon-btn hero-copy-icon-btn"
              type="button"
              aria-label="Copy npub"
              title="Copy npub"
              data-testid="copy-pubkey"
              on:click={copyPubkey}
            >
              <span class="copy-icon" aria-hidden="true">
                {#if copiedValue === 'pubkey'}
                  <Check size={16} strokeWidth={2.3} />
                {:else}
                  <Copy size={16} strokeWidth={2.2} />
                {/if}
              </span>
            </button>
          </div>
        </div>

        <div class="hero-stat-card hero-device-card">
          <div class="panel-kicker">This device</div>
          <input
            class="text-input hero-device-name-input"
            data-testid="node-name-input"
            bind:value={nodeNameDraft}
            on:input={() => debounce('nodeName', () => onUpdateSettings({ nodeName: nodeNameDraft }))}
          />
          <div class="config-path hero-device-preview">{nodeNamePreviewText(nodeNameDraft, state)}</div>
          <div class="config-path">{state.tunnelIp} • {state.endpoint}</div>
        </div>
      </div>

      <div class="row status-row">
        {#if vpnControlSupported}
          <span class={`badge ${state.daemonRunning ? 'ok' : 'bad'}`}>
            Daemon {state.daemonRunning ? 'Running' : 'Stopped'}
          </span>
          <span class={`badge ${state.sessionActive ? 'ok' : 'bad'}`}>
            VPN {state.sessionActive ? 'On' : 'Off'}
          </span>
          <span class={`badge ${state.relayConnected ? 'ok' : 'muted'}`}>
            Relays {state.relayConnected ? 'Connected' : 'Disconnected'}
          </span>
          <span class="badge muted" data-testid="mesh-badge">
            Mesh {state.connectedPeerCount}/{state.expectedPeerCount}
          </span>
        {:else}
          <span class="badge muted">Platform {platformLabel(state.platform)}</span>
          <span class="badge muted">Config editing enabled</span>
          <span class="badge muted">Tunnel control unavailable</span>
        {/if}
      </div>
      {#if heroDetailText(state)}
        <div class="identity-status" data-testid="session-status-text">
          {heroDetailText(state)}
        </div>
      {/if}
    {:else}
      <div class="panel-kicker">Loading</div>
      <div class="row hero-title-row">
        <h1>Starting Nostr VPN</h1>
      </div>
      <div class="hero-subtitle">Loading config, daemon state, and local mesh status.</div>
    {/if}
  </section>

  {#if serviceRepairErrorText(error, state)}
    <section class="panel error">{serviceRepairErrorText(error, state)}</section>
  {/if}

  {#if state}
    {@const activeNetworkView = activeNetwork(state)}

    {#if serviceInstallRecommended || serviceEnableRecommended || serviceRepairPromptRecommended}
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
            {serviceRepairPromptRecommended
              ? 'Reinstall the service to finish this app update'
              : serviceSetupRequired
              ? 'Install once for reliable background VPN'
              : 'Enable the service to keep VPN control out of the GUI process'}
          </div>
          <div class="service-panel-text">
            {serviceRepairPromptRecommended
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
          >
            {serviceRepairPromptRecommended
              ? serviceRepairRetryAfterInstall && !state.sessionActive
                ? 'Reinstall service and retry'
                : state.sessionActive
                ? 'Reinstall service'
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
            >
              Disable service
            </button>
          {/if}
          <button
            class="btn ghost"
            data-testid="uninstall-service-btn"
            on:click={onUninstallSystemService}
            disabled={!state.serviceInstalled}
          >
            Uninstall
          </button>
        </div>
      </section>
    {/if}

    <section class="panel spotlight-panel">
      <div class="section-title-row">
        <div>
          <div class="panel-kicker">Active network</div>
          <h2>{activeNetworkView.name}</h2>
        </div>
        <div class="section-meta">
          {onlineDeviceSummary(activeNetworkView.onlineCount, activeNetworkView.expectedCount)}
        </div>
      </div>

      <div class="spotlight-meta-grid">
        <div class="spotlight-meta-card spotlight-profile-card">
          <div class="panel-kicker">Profile</div>
          <div class="spotlight-profile-fields">
            <label class="field-label" for={`active-network-name-${activeNetworkView.id}`}>Name</label>
            <input
              id={`active-network-name-${activeNetworkView.id}`}
              class="text-input active-network-name-input"
              data-testid="network-name-input"
              value={networkNameDrafts[activeNetworkView.id] ?? activeNetworkView.name}
              on:input={(event) =>
                onNetworkNameInput(activeNetworkView.id, (event.currentTarget as HTMLInputElement).value)}
            />
            <label class="field-label" for={`active-network-mesh-${activeNetworkView.id}`}>Mesh ID</label>
            <div class="inline-copy-field">
              <input
                id={`active-network-mesh-${activeNetworkView.id}`}
                class={`text-input network-mesh-id-input ${meshIdDraftError(activeNetworkView.id) ? 'text-input-invalid' : ''}`}
                data-testid="active-network-mesh-id-input"
                value={formatMeshIdDraftForDisplay(
                  networkIdDrafts[activeNetworkView.id] ?? '',
                  activeNetworkView.networkId,
                )}
                on:input={(event) =>
                  onNetworkMeshIdInput(activeNetworkView.id, (event.currentTarget as HTMLInputElement).value)}
                on:blur={(event) =>
                  commitNetworkMeshId(activeNetworkView.id, (event.currentTarget as HTMLInputElement).value)}
                on:keydown={(event) =>
                  event.key === 'Enter' &&
                  commitNetworkMeshId(activeNetworkView.id, (event.currentTarget as HTMLInputElement).value)}
              />
              <button class="btn copy-btn" data-testid="copy-mesh-id" on:click={copyMeshId}>
                <span class="copy-icon" aria-hidden="true">
                  {#if copiedValue === 'meshId'}
                    <Check size={16} strokeWidth={2.3} />
                  {:else}
                    <Copy size={16} strokeWidth={2.2} />
                  {/if}
                </span>
                <span>{copiedValue === 'meshId' ? 'Copied' : 'Copy Mesh ID'}</span>
              </button>
            </div>
            <div class={`config-path ${meshIdDraftError(activeNetworkView.id) ? 'mesh-id-note-error' : ''}`}>
              {meshIdHelperText(activeNetworkView.id, activeNetworkView.networkId)}
            </div>
          </div>
          <div class="config-path">{networkPeerSummary(activeNetworkView)}</div>
          <div class="config-path">
            Stable identifier used for tunnel addressing and matching the right mesh.
          </div>
        </div>
        <div class="spotlight-meta-card spotlight-share-card">
          <div class="panel-kicker">Join & share</div>
          <div class="spotlight-meta-value">Copy, scan, or pair</div>
          <div class="config-path">
            Includes the Mesh ID, your npub, and the relay list for {activeNetworkView.name}.
          </div>
          <div class="config-path" data-testid="network-admin-summary">
            {networkAdminSummary(activeNetworkView)}
          </div>
          <label class="toggle-row">
            <input
              type="checkbox"
              checked={activeNetworkView.joinRequestsEnabled}
              disabled={!activeNetworkView.localIsAdmin}
              on:change={(event) =>
                onToggleJoinRequests(
                  activeNetworkView.id,
                  (event.currentTarget as HTMLInputElement).checked,
                )}
            />
            <div>Listen for join requests</div>
          </label>
          <div class="config-path">
            Join requests from invite holders will appear here.
          </div>
          {#if activeNetworkView.inboundJoinRequests.length > 0}
            <div class="lan-title">Pending join requests</div>
            <div class="stack rows">
              {#each activeNetworkView.inboundJoinRequests as request}
                <div class="item-row" data-testid="join-request-row">
                  <div class="item-main">
                    <div class="item-title">
                      {request.requesterNodeName || 'Pending device'}
                    </div>
                    <div class="peer-npub-row">
                      <div class="peer-npub-text">{request.requesterNpub}</div>
                      <button
                        class="btn ghost icon-btn peer-npub-copy-btn"
                        type="button"
                        aria-label="Copy peer npub"
                        title="Copy peer npub"
                        data-testid="copy-peer-npub"
                        on:click={() => copyPeerNpub(request.requesterNpub)}
                      >
                        <span class="copy-icon" aria-hidden="true">
                          {#if copiedValue === 'peerNpub' && copiedPeerNpub === request.requesterNpub}
                            <Check size={16} strokeWidth={2.3} />
                          {:else}
                            <Copy size={16} strokeWidth={2.2} />
                          {/if}
                        </span>
                      </button>
                    </div>
                    <div class="item-sub">
                      requested {request.requestedAtText}
                    </div>
                  </div>
                  <button
                    class="btn"
                    data-testid="accept-join-request"
                    disabled={!activeNetworkView.localIsAdmin}
                    on:click={() => onAcceptJoinRequest(activeNetworkView.id, request.requesterNpub)}
                  >
                    Accept
                  </button>
                </div>
              {/each}
            </div>
          {/if}
          <InviteSharePanel
            {state}
            {activeNetworkView}
            {inviteQrDataUrl}
            {inviteQrError}
            {inviteInputDraft}
            {inviteScanOpen}
            {inviteScanStatus}
            {inviteScanError}
            {participantInputDrafts}
            {participantAddAliasDrafts}
            {copiedValue}
            {copiedPeerNpub}
            {lanPairingDisplayRemainingSecs}
            {formatCountdown}
            {copyInvite}
            {copyPeerNpub}
            {onStartLanPairing}
            {onStopLanPairing}
            {onJoinLanPeer}
            {onRequestNetworkJoin}
            {onInviteInput}
            {onInvitePaste}
            {onImportInvite}
            {onStartInviteScan}
            {onChooseInviteQrImage}
            {onCloseInviteScan}
            {onInviteScanFileSelected}
            bind:inviteScanInput
            bind:inviteScanVideo
            {onAddParticipant}
            {lanPairingHelpText}
          />
        </div>
      </div>

      {#if activeNetworkView.participants.length === 0}
        <div class="item-row network-empty-state">
          <div class="item-main">
            <div class="item-title">No devices yet</div>
            <div class="item-sub">Import an invite, start LAN pairing, or add a participant npub to start building the active mesh.</div>
          </div>
        </div>
      {:else}
        <div class="stack rows">
          {#each activeNetworkView.participants as participant}
            <div class="item-row" data-testid="participant-row">
              <div class="item-main">
                <div class="peer-npub-row">
                  <div class="peer-npub-text" data-testid="participant-npub">{participant.npub}</div>
                  <button
                    class="btn ghost icon-btn peer-npub-copy-btn"
                    type="button"
                    aria-label="Copy peer npub"
                    title="Copy peer npub"
                    data-testid="copy-peer-npub"
                    on:click={() => copyPeerNpub(participant.npub)}
                  >
                    <span class="copy-icon" aria-hidden="true">
                      {#if copiedValue === 'peerNpub' && copiedPeerNpub === participant.npub}
                        <Check size={16} strokeWidth={2.3} />
                      {:else}
                        <Copy size={16} strokeWidth={2.2} />
                      {/if}
                    </span>
                  </button>
                </div>
                <div class="row alias-row">
                  <input
                    class="text-input alias-input"
                    value={participantAliasDrafts[participant.pubkeyHex] ?? participant.magicDnsAlias}
                    data-testid="participant-alias-input"
                    on:input={(event) =>
                      onParticipantAliasInput(
                        participant.npub,
                        participant.pubkeyHex,
                        (event.currentTarget as HTMLInputElement).value,
                      )}
                  />
                  {#if state.magicDnsSuffix}
                    <span class="alias-suffix">.{state.magicDnsSuffix}</span>
                  {/if}
                </div>
                <div class="item-sub" data-testid="participant-status-text">
                  {participant.magicDnsName || participant.magicDnsAlias || 'No alias'} | {participant.statusText} | {participant.lastSignalText} | {participant.tunnelIp}
                  | {participantTrafficText(participant)}
                  {#if participant.relayPathActive && participant.runtimeEndpoint}
                    | relay {participant.runtimeEndpoint}
                  {/if}
                  {#if participant.advertisedRoutes.length > 0}
                    | routes {participant.advertisedRoutes.join(', ')}
                  {/if}
                </div>
              </div>
              <div class="participant-badges">
                <span
                  class={`badge participant-badge ${participantBadgeClass(participant.state)}`}
                  data-testid="participant-state"
                >
                  {participantTransportBadgeText(participant)}
                </span>
                <span
                  class={`badge participant-badge ${participantBadgeClass(participant.presenceState)}`}
                  data-testid="participant-presence-state"
                >
                  {participantPresenceBadgeText(participant)}
                </span>
                {#if participant.isAdmin}
                  <span class="badge participant-badge ok" data-testid="participant-admin-badge">
                    Admin
                  </span>
                {/if}
                {#if participant.relayPathActive}
                  <span class="badge participant-badge warn">Relay fallback</span>
                {/if}
                {#if participant.offersExitNode}
                  <span class="badge participant-badge warn">Private exit</span>
                {/if}
                {#if state.exitNode === participant.npub}
                  <span class="badge participant-badge ok">Selected exit</span>
                {/if}
              </div>
              {#if activeNetworkView.localIsAdmin}
                <button
                  class="btn ghost"
                  data-testid="participant-toggle-admin"
                  on:click={() => onToggleAdmin(activeNetworkView.id, participant)}
                >
                  {participant.isAdmin ? 'Remove admin' : 'Make admin'}
                </button>
              {/if}
              <button
                class="btn ghost icon-btn"
                data-testid="participant-remove"
                title="Delete participant"
                aria-label="Delete participant"
                disabled={!activeNetworkView.localIsAdmin}
                on:click={() => runAction(() => removeParticipant(activeNetworkView.id, participant.npub))}
              >
                <Trash2 size={16} strokeWidth={2.2} />
              </button>
            </div>
          {/each}
        </div>
      {/if}

    </section>

    <section class="panel exit-node-panel">
      <div class="section-title-row">
        <div>
          <div class="panel-kicker">Routing</div>
          <h2>Routing & Sharing</h2>
        </div>
        <div class="section-meta">{routingSectionMetaText(state)}</div>
      </div>

      <div class="field-grid">
        <div class="field-panel">
          <div class="field-label">Current Mode</div>
          <div class="config-path">{routingModeStatusText(state)}</div>
        </div>

        <div class="field-panel">
          <label class="toggle-row">
            <input
              type="checkbox"
              checked={state.advertiseExitNode}
              on:change={(event) =>
                onUpdateSettings({
                  advertiseExitNode: (event.currentTarget as HTMLInputElement).checked,
                })}
            />
            <div>Advertise this device as a private exit node</div>
          </label>
          <div class="config-path settings-note">{offerExitNodeStatusText(state)}</div>
        </div>

        <label class="field-span">
          <span>Advertised Routes</span>
          <input
            class="text-input"
            placeholder="10.0.0.0/24, 192.168.0.0/24"
            bind:value={advertisedRoutesDraft}
            on:input={() =>
              debounce('advertisedRoutes', () =>
                onUpdateSettings({ advertisedRoutes: advertisedRoutesDraft }))}
          />
          <div class="config-path">{additionalRoutesStatusText(state)}</div>
        </label>

        <div class="field-span field-panel exit-node-panel-body">
          <div class="field-label">Use A Peer Exit Node</div>
          <div class="config-path">{selectedExitNodeStatusText(state)}</div>
          <input
            class="text-input"
            placeholder="Search peers by alias, npub, or tunnel IP"
            data-testid="exit-node-search"
            bind:value={exitNodeSearch}
          />
          <div class="exit-node-list" data-testid="exit-node-select">
            <button
              class={`exit-node-card ${!state.exitNode ? 'selected' : ''}`}
              type="button"
              on:click={() => onSelectExitNode('')}
            >
              <div class="row spread">
                <div class="item-title">No exit node</div>
                <span class="badge muted">Direct mesh</span>
              </div>
              <div class="item-sub">Keep default-route traffic off peer relays and use mesh routing only.</div>
            </button>

            {#each filteredExitNodeCandidates(state, exitNodeSearch) as participant}
              <button
                class={`exit-node-card ${
                  state.exitNode === participant.npub ? 'selected' : ''
                } ${!participant.offersExitNode ? 'disabled' : ''}`}
                type="button"
                on:click={() => onSelectExitNode(participant.npub)}
                disabled={!participant.offersExitNode}
              >
                <div class="row spread">
                  <div class="item-title">
                    {participant.magicDnsName || participant.magicDnsAlias || participant.npub}
                  </div>
                  <span class={`badge ${exitNodeAvailabilityClass(participant)}`}>
                    {exitNodeAvailabilityText(participant)}
                  </span>
                </div>
                <div class="item-sub">
                  {participant.npub} | {participant.statusText} | {participant.lastSignalText} | {participant.tunnelIp}
                </div>
              </button>
            {/each}

            {#if filteredExitNodeCandidates(state, exitNodeSearch).length === 0}
              <div class="config-path">No peers match that search.</div>
            {/if}
          </div>
        </div>
      </div>
    </section>

    <SavedNetworksPanel
      bind:newNetworkName
      {state}
      inactiveNetworks={inactiveNetworks(state)}
      {networkNameDrafts}
      {networkIdDrafts}
      {participantInputDrafts}
      {participantAddAliasDrafts}
      {participantAliasDrafts}
      {copiedValue}
      {copiedPeerNpub}
      formatMeshIdForDisplay={formatMeshIdForDisplay}
      formatMeshIdDraftForDisplay={formatMeshIdDraftForDisplay}
      networkPeerSummary={networkPeerSummary}
      networkAdminSummary={networkAdminSummary}
      meshIdDraftError={meshIdDraftError}
      meshIdHelperText={meshIdHelperText}
      onNetworkNameInput={onNetworkNameInput}
      onNetworkMeshIdInput={onNetworkMeshIdInput}
      commitNetworkMeshId={commitNetworkMeshId}
      onToggleJoinRequests={onToggleJoinRequests}
      copyPeerNpub={copyPeerNpub}
      onAcceptJoinRequest={onAcceptJoinRequest}
      onAddParticipant={onAddParticipant}
      onAddNetwork={onAddNetwork}
      onRequestNetworkJoin={onRequestNetworkJoin}
      onRemoveParticipant={(networkId, npub) => runAction(() => removeParticipant(networkId, npub))}
      onParticipantAliasInput={onParticipantAliasInput}
      runAction={runAction}
      removeNetwork={removeNetwork}
      setNetworkEnabled={setNetworkEnabled}
    />
    <!-- {#if network.localIsAdmin}
    <span class="badge ok" data-testid="saved-network-admin-badge">
      Admin
    </span>
    -->

    {#if state.vpnSessionControlSupported}
      <details class="panel collapsible-panel" open={state.health.length > 0}>
        <summary class="collapsible-summary">
          <div>
            <div class="panel-kicker">Advanced</div>
            <h2>Diagnostics</h2>
          </div>
          <div class="section-meta">{healthSummaryText(state)}</div>
        </summary>

        <div class="collapsible-body diagnostics-panel">
          <div class="row status-row diagnostics-badges">
            <span class="badge muted">
              IF {state.network.defaultInterface || 'unknown'}
            </span>
            <span
              class={`badge ${
                state.network.captivePortal === true
                  ? 'bad'
                  : state.network.captivePortal === false
                    ? 'ok'
                    : 'muted'
              }`}
            >
              {state.network.captivePortal === true
                ? 'Captive portal'
                : state.network.captivePortal === false
                  ? 'Open internet'
                  : 'Portal unknown'}
            </span>
            <span class={`badge ${state.portMapping.activeProtocol ? 'ok' : 'muted'}`}>
              Mapping {state.portMapping.activeProtocol || 'none'}
            </span>
          </div>

          <div class="diagnostics-copy">
            <div class="config-path">
              Local addresses:
              {state.network.primaryIpv4 || 'no IPv4'}
              {#if state.network.primaryIpv6}
                | {state.network.primaryIpv6}
              {/if}
            </div>
            <div class="config-path">
              Gateway:
              {state.network.gatewayIpv4 || state.network.gatewayIpv6 || 'unknown'}
            </div>
            <div class="config-path">
              External endpoint:
              {state.portMapping.externalEndpoint || 'stun / direct only'}
            </div>
          </div>

          {#if state.health.length === 0}
            <div class="config-path" data-testid="health-empty">Daemon reports no active health warnings.</div>
          {:else}
            <div class="stack rows">
              {#each state.health as issue}
                <div class="health-card" data-testid="health-issue">
                  <div class="row spread health-card-header">
                    <div class="item-title">{issue.summary}</div>
                    <span class={`badge ${healthBadgeClass(issue.severity)}`}>{issue.severity}</span>
                  </div>
                  <div class="item-sub">{issue.detail}</div>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      </details>
    {/if}

    {#if state.serviceSupported && !serviceInstallRecommended && !serviceEnableRecommended}
      <details class="panel collapsible-panel service-panel" data-testid="service-panel">
        <summary class="collapsible-summary">
          <div>
            <div class="panel-kicker">Advanced</div>
            <h2>Background Service</h2>
          </div>
          <div class="section-meta">{serviceMetaText(state)}</div>
        </summary>

        <div class="collapsible-body">
          <div class="row status-row">
            <span class="badge ok">Installed</span>
            <span class={`badge ${serviceLifecycleBadgeClass(state)}`}>
              {serviceLifecycleBadgeText(state)}
            </span>
            <span class={`badge ${state.daemonRunning ? 'ok' : 'muted'}`}>
              Daemon {state.daemonRunning ? 'reachable' : 'idle'}
            </span>
          </div>

          <div class="service-panel-copy">
            <div class="service-panel-title">
              Background service manages privileged VPN runtime operations.
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
              class="btn"
              data-testid="install-service-btn"
              on:click={() =>
                serviceEnableRecommended ? onEnableSystemService() : onInstallSystemService()}
            >
              {serviceEnableRecommended ? 'Enable service' : 'Reinstall service'}
            </button>
            {#if state.serviceEnablementSupported && state.serviceInstalled && !state.serviceDisabled}
              <button
                class="btn ghost"
                data-testid="disable-service-btn"
                on:click={onDisableSystemService}
              >
                Disable service
              </button>
            {/if}
            <button
              class="btn ghost"
              data-testid="uninstall-service-btn"
              on:click={onUninstallSystemService}
            >
              Uninstall
            </button>
          </div>
        </div>
      </details>
    {/if}

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
                <span
                  class={`badge ${state.relayOperator.activeSessionCount > 0 ? 'warn' : 'muted'}`}
                >
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

    <details class="panel collapsible-panel">
      <summary class="collapsible-summary">
        <div>
          <div class="panel-kicker">Advanced</div>
          <h2>Relays</h2>
        </div>
        <div class="section-meta relay-health">
          <span class="ok-text">{state.relaySummary.up}/{state.relays.length} connected</span>
        </div>
      </summary>

      <div class="collapsible-body">
        <div class="row form-row">
          <input
            class="text-input"
            placeholder="Add relay URL"
            data-testid="relay-input"
            bind:value={relayInput}
            on:keydown={(event) => event.key === 'Enter' && onAddRelay()}
          />
          <button class="btn" data-testid="relay-add" on:click={onAddRelay}>Add</button>
        </div>

        <div class="stack rows">
          {#each state.relays as relay}
            <div class="item-row" data-testid="relay-row">
              <div class="item-main">
                <div class="item-title relay-url">{relay.url}</div>
                {#if relay.state !== 'unknown' && relay.statusText}
                  <div class="item-sub">{relay.statusText}</div>
                {/if}
              </div>
              <span class={`badge ${relay.state === 'up' ? 'ok' : relay.state === 'down' ? 'bad' : relay.state === 'checking' ? 'warn' : 'muted'}`}>
                {relay.state}
              </span>
              <button
                class="btn ghost icon-btn"
                data-testid="relay-remove"
                title="Delete relay"
                aria-label="Delete relay"
                on:click={() => runAction(() => removeRelay(relay.url))}
              >
                <Trash2 size={16} strokeWidth={2.2} />
              </button>
            </div>
          {/each}
        </div>
      </div>
    </details>

    {#if state.vpnSessionControlSupported}
      <details class="panel collapsible-panel">
        <summary class="collapsible-summary">
          <div>
            <div class="panel-kicker">Connection</div>
            <h2>Session & Relays</h2>
          </div>
          <div class="section-meta">Startup & relay behavior</div>
        </summary>

        <div class="collapsible-body">
          <label class="toggle-row">
            <input
              type="checkbox"
              checked={state.usePublicRelayFallback}
              on:change={(event) =>
                onUpdateSettings({
                  usePublicRelayFallback: (event.target as HTMLInputElement).checked,
                })}
            />
            <span>Use public relay fallback when direct connection fails</span>
          </label>
          <div class="config-path settings-note">{publicRelayFallbackStatusText(state)}</div>

          <label class="toggle-row">
            <input
              type="checkbox"
              checked={state.autoconnect}
              on:change={(event) =>
                onUpdateSettings({
                  autoconnect: (event.currentTarget as HTMLInputElement).checked,
                })}
            />
            <span>Auto-connect session on app start</span>
          </label>

          <div class="section-meta">Current fallback</div>
          <div class="config-path settings-note">{relayFallbackSummaryText(activeNetworkView)}</div>
          {#if relayFallbackParticipants(activeNetworkView).length > 0}
            <div class="stack rows">
              {#each relayFallbackParticipants(activeNetworkView) as participant}
                <div class="item-row">
                  <div class="item-main">
                    <div class="item-title">
                      {participant.magicDnsName || participant.magicDnsAlias || participant.npub}
                    </div>
                    <div class="item-sub">
                      {participant.runtimeEndpoint
                        ? `relay ${participant.runtimeEndpoint}`
                        : 'relay fallback active'} | {participantTrafficText(participant)}
                    </div>
                  </div>
                  <div class="participant-badges">
                    <span class="badge participant-badge warn">Relay fallback</span>
                  </div>
                </div>
              {/each}
            </div>
          {/if}
        </div>
      </details>
    {/if}

    <details class="panel collapsible-panel">
      <summary class="collapsible-summary">
        <div>
          <div class="panel-kicker">System</div>
          <h2>Device & App</h2>
        </div>
        <div class="section-meta">
          {cliInstallSupported || startupSettingsSupported || trayBehaviorSupported
            ? 'Node, DNS & startup'
            : 'Node & DNS'}
        </div>
      </summary>

      <div class="collapsible-body">
        <div class="row settings-action-row">
          <div class="config-path" data-testid="app-version">Version: {state.appVersion}</div>
        </div>
        <div class="row settings-action-row">
          <div class="config-path">Config: {state.configPath}</div>
        </div>
        {#if cliInstallSupported}
          <div class="row spread settings-action-row">
            <div class="config-path">Terminal CLI</div>
            <div class="row cli-actions-row">
              <button class="btn" data-testid="install-cli-btn" on:click={onInstallCli}>
                {state.cliInstalled ? 'Reinstall CLI' : 'Install CLI'}
              </button>
              <button
                class="btn ghost"
                data-testid="uninstall-cli-btn"
                on:click={onUninstallCli}
                disabled={!state.cliInstalled}
              >
                Uninstall CLI
              </button>
            </div>
          </div>
          {#if cliActionStatus}
            <div class="config-path">{cliActionStatus}</div>
          {/if}
        {/if}
        <div class="config-path" data-testid="magic-dns-status">DNS: {state.magicDnsStatus}</div>

        {#if startupSettingsSupported}
          <label class="toggle-row">
            <input
              type="checkbox"
              data-testid="autostart-toggle"
              checked={state.launchOnStartup}
              disabled={!autostartReady || autostartUpdating}
              on:change={(event) =>
                onToggleAutostart((event.currentTarget as HTMLInputElement).checked)}
            />
            <span>Launch on system startup</span>
          </label>
        {/if}

        {#if trayBehaviorSupported}
          <label class="toggle-row">
            <input
              type="checkbox"
              checked={state.closeToTrayOnClose}
              on:change={(event) =>
                onUpdateSettings({
                  closeToTrayOnClose: (event.currentTarget as HTMLInputElement).checked,
                })}
            />
            <span>Keep running in menu bar when window is closed</span>
          </label>
        {/if}

        <div class="field-grid">
          <label>
            <span>MagicDNS Suffix (Optional)</span>
            <input
              class="text-input"
              data-testid="magic-dns-suffix-input"
              bind:value={magicDnsSuffixDraft}
              on:input={() =>
                debounce('magicDnsSuffix', () =>
                  onUpdateSettings({ magicDnsSuffix: magicDnsSuffixDraft }))}
            />
          </label>

          <label>
            <span>Endpoint</span>
            <input
              class="text-input"
              bind:value={endpointDraft}
              on:input={() => debounce('endpoint', () => onUpdateSettings({ endpoint: endpointDraft }))}
            />
          </label>

          <label>
            <span>Tunnel IP</span>
            <input
              class="text-input"
              bind:value={tunnelIpDraft}
              on:input={() => debounce('tunnelIp', () => onUpdateSettings({ tunnelIp: tunnelIpDraft }))}
            />
          </label>

          <label>
            <span>Listen Port</span>
            <input
              class="text-input"
              bind:value={listenPortDraft}
              on:input={() =>
                debounce('listenPort', async () => {
                  const parsed = Number.parseInt(listenPortDraft, 10)
                  if (!Number.isNaN(parsed) && parsed > 0 && parsed <= 65535) {
                    await onUpdateSettings({ listenPort: parsed })
                  }
                })}
            />
          </label>
        </div>
      </div>
    </details>
  {/if}
</main>
