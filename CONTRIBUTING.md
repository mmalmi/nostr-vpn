# Contributing

## StartOS Package

The StartOS package lives in `startos/` and uses the Dockerfile at
`umbrel/Dockerfile` to build the service image. The package supports `x86_64`
and `aarch64`.

Install the StartOS packaging prerequisites from the official packaging guide,
then run:

```bash
npm ci
npm run check
npm run build
make
```

Useful targeted builds:

```bash
make x86
make arm
make clean
```

To produce the versioned x86_64 and aarch64 artifacts used by tagged releases:

```bash
just release-startos
```

The local release pipeline includes the same StartOS build. Tagged GitHub
releases build both architectures on native runners, sign them with the
`STARTOS_DEV_KEY` repository secret, and attach the `.s9pk` files to the
release.

`make install` sideloads the newest local `.s9pk` to the StartOS host configured
in `~/.startos/config.yaml`.

Before opening a Start9 Community Registry PR, verify:

- `npm run check` passes.
- `npm run build` passes.
- Fresh `.s9pk` files are built from the current commit.
- The package has been installed on StartOS, started, launched through its Web UI
  interface, backed up, restored, stopped, uninstalled, and reinstalled.
