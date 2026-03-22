#!/usr/bin/env node

import process from 'node:process'

import { prepareSidecar } from './prepare-sidecar-lib.mjs'

prepareSidecar({
  release: process.argv.slice(2).includes('--release'),
})
