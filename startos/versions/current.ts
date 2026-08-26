import { IMPOSSIBLE, VersionInfo } from '@start9labs/start-sdk'

export const currentVersion = VersionInfo.of({
  version: '4.1.9:0',
  releaseNotes: {
    en_US: 'Initial StartOS package for Nostr VPN.',
  },
  migrations: {
    up: async () => {},
    down: IMPOSSIBLE,
  },
})
