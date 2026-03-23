export function remainingSecsFromDeadline(deadlineMs, nowMs) {
  if (deadlineMs == null) {
    return 0
  }

  const remainingMs = Math.max(deadlineMs - nowMs, 0)
  return Math.ceil(remainingMs / 1000)
}

export function lanPairingDeadlineFromSnapshot(
  previousDeadlineMs,
  active,
  remainingSecs,
  nowMs,
) {
  if (!active) {
    return null
  }

  const candidateDeadlineMs = nowMs + Math.max(remainingSecs, 0) * 1000
  if (previousDeadlineMs == null) {
    return candidateDeadlineMs
  }

  const currentRemainingSecs = remainingSecsFromDeadline(previousDeadlineMs, nowMs)

  // Treat a larger backend countdown as a fresh pairing start rather than
  // stretching the existing timer forward by poll jitter.
  if (remainingSecs > currentRemainingSecs + 1) {
    return candidateDeadlineMs
  }

  return Math.min(previousDeadlineMs, candidateDeadlineMs)
}
