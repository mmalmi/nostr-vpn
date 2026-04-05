const STALE_SERVICE_MARKERS = [
  'restart the daemon with a newer nvpn binary',
  'older nvpn daemon binary is still running',
]

const UNRESPONSIVE_SERVICE_MARKERS = [
  'daemon did not acknowledge control request',
  'daemon did not report result for',
  'daemon acknowledged control request but did not',
]

const normalizedError = (error) => String(error ?? '').trim()
const staleServiceError = (error) =>
  STALE_SERVICE_MARKERS.some((marker) => normalizedError(error).toLowerCase().includes(marker))
const unresponsiveServiceError = (error) =>
  UNRESPONSIVE_SERVICE_MARKERS.some((marker) =>
    normalizedError(error).toLowerCase().includes(marker)
  )

const installedServiceBinaryVersion = (state) => {
  const serviceBinaryVersion = String(state?.serviceBinaryVersion ?? '').trim()
  if (serviceBinaryVersion.length > 0) {
    return serviceBinaryVersion
  }

  return String(state?.daemonBinaryVersion ?? '').trim()
}

const serviceBinaryVersionMismatch = (state) => {
  if (
    !state?.serviceSupported ||
    !state?.serviceInstalled ||
    !state?.serviceRunning ||
    !state?.daemonRunning
  ) {
    return false
  }

  const appVersion = String(state.appVersion ?? '').trim()
  const serviceBinaryVersion = installedServiceBinaryVersion(state)
  return appVersion.length > 0 && serviceBinaryVersion.length > 0 && serviceBinaryVersion !== appVersion
}

const serviceVersionMismatchText = (state) => {
  const appVersion = String(state?.appVersion ?? '').trim()
  const serviceBinaryVersion = installedServiceBinaryVersion(state)

  if (
    appVersion.length > 0 &&
    serviceBinaryVersion.length > 0 &&
    appVersion !== serviceBinaryVersion
  ) {
    return `Background service version (${serviceBinaryVersion}) does not match this app (${appVersion}). Reinstall or update so both use the same version, then try turning VPN on again.`
  }

  return 'Background service version does not match this app. Reinstall or update so both use the same version, then try turning VPN on again.'
}

export const serviceRepairRecommended = (error, state) => {
  if (!state?.serviceSupported || !state?.serviceInstalled) {
    return false
  }

  return serviceBinaryVersionMismatch(state) || staleServiceError(error)
}

export const serviceRepairRetryRecommended = (error) => unresponsiveServiceError(error)

export const serviceRepairRetryRecovered = (error, state) =>
  unresponsiveServiceError(error) &&
  !!state?.daemonRunning &&
  (!!state?.sessionActive || !!state?.serviceRunning)

export const serviceRepairErrorText = (error, state) => {
  const normalized = normalizedError(error)
  const versionMismatch = serviceBinaryVersionMismatch(state)
  const staleService = staleServiceError(error)
  const controlTimeout = unresponsiveServiceError(error)

  if (!normalized && versionMismatch) {
    return serviceVersionMismatchText(state)
  }

  if (normalized && staleService) {
    return serviceVersionMismatchText(state)
  }

  if (controlTimeout) {
    return 'Background service did not respond in time. Try turning VPN on again. If it keeps happening, restart or reinstall the service.'
  }

  if (!normalized) {
    return normalizedError(error)
  }
  return normalized
}
