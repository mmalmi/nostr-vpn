# StartOS package development

The StartOS package lives in `startos/` and uses the Dockerfile at
`umbrel/Dockerfile` to build the service image. The package supports `x86_64`
and `aarch64`.

Install the prerequisites from the StartOS
[environment setup guide](https://docs.start9.com/packaging/0.4.0.x/environment-setup.html),
then build both package architectures:

```bash
make
```

The Makefile installs Node dependencies and runs the TypeScript check and build
before packaging.

Useful targeted builds:

```bash
make x86
make arm
make clean
```

To produce versioned, validated x86_64 and aarch64 artifacts:

```bash
just release-startos
```

This command builds and validates both architectures; it does not publish them.

Before opening a Start9 Community Registry PR, verify:

- `make` produces fresh `.s9pk` files from the current commit.
- The package has been installed on StartOS, started, launched through its Web UI
  interface, backed up, restored, stopped, uninstalled, and reinstalled.
