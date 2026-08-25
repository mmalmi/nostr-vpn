import { setupManifest } from '@start9labs/start-sdk'
import { long, short } from './i18n'

export const manifest = setupManifest({
  id: 'nostr-vpn',
  title: 'Nostr VPN',
  license: 'MIT',
  packageRepo: 'https://github.com/mmalmi/nostr-vpn',
  upstreamRepo: 'https://github.com/mmalmi/nostr-vpn',
  marketingUrl: 'https://github.com/mmalmi/nostr-vpn',
  donationUrl: null,
  description: { short, long },
  virtualNetworking: true,
  volumes: ['main'],
  images: {
    app: {
      source: {
        dockerBuild: {
          workdir: '.',
          dockerfile: './umbrel/Dockerfile',
        },
      },
      arch: ['x86_64', 'aarch64'],
    },
  },
  dependencies: {},
})
