export const sessionToggleVisualState = (sessionActive, pendingTarget = null) => {
  const active = Boolean(sessionActive)
  const pending = typeof pendingTarget === 'boolean' && pendingTarget !== active
  return {
    active,
    pending,
    className: active ? 'on' : 'off',
    label: pending ? `VPN ${pendingTarget ? 'Starting' : 'Stopping'}` : `VPN ${active ? 'On' : 'Off'}`,
  }
}
