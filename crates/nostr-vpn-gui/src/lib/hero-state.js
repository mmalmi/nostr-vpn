/**
 * @typedef {import('./types').UiState} UiState
 */

/**
 * @param {UiState} state
 * @param {{ serviceInstallRecommended?: boolean, serviceEnableRecommended?: boolean }} options
 * @returns {'Service required' | 'Connected' | 'Connecting' | 'Disconnected'}
 */
export function heroStateText(state, options = {}) {
  const serviceInstallRecommended = options.serviceInstallRecommended ?? false
  const serviceEnableRecommended = options.serviceEnableRecommended ?? false

  if ((serviceInstallRecommended || serviceEnableRecommended) && !state.sessionActive) {
    return 'Service required'
  }
  if (state.meshReady) {
    return 'Connected'
  }
  if (state.sessionActive) {
    return 'Connecting'
  }
  return 'Disconnected'
}

/**
 * @param {UiState} state
 * @returns {string}
 */
export function heroStatusDetailText(state) {
  const sessionStatus = state.sessionStatus?.trim() ?? ''

  if (!sessionStatus) {
    return ''
  }

  return sessionStatus
}
