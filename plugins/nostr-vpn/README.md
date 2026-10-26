# Nostr VPN agent plugin

The plugin teaches an agent to use the existing command line tool. It contains
one portable skill, no background hooks, and no hosted service or API key.
Install the tool on the agent's execution host using the [workflow guide](https://github.com/mmalmi/nostr-vpn/blob/master/docs/agents.md).
Installing the plugin alone does not install binaries or start a service.

## Codex and ChatGPT desktop

```sh
codex plugin marketplace add mmalmi/nostr-vpn
codex plugin add nostr-vpn@nostr-vpn-plugins
```

Restart the agent session and select Nostr VPN, or ask it to use the
`nostr-vpn` skill. For a local checkout, replace the repository argument with
`.` while in this repository. The repository also exposes the plugin through
`.agents/plugins/marketplace.json` in supported desktop clients.

OpenAI marks plugins that call local programs as **Desktop only**. A dot needs a
supported local task on a connected computer for this plugin; installing it does
not give a cloud-only dot access to your computer or networking privileges.
Public-directory submission is separate from installing this repository.

## Claude Code

```sh
claude plugin marketplace add mmalmi/nostr-vpn
claude plugin install nostr-vpn@nostr-vpn-plugins
```

Start a new session, then invoke `/nostr-vpn:nostr-vpn` with your request.
For local evaluation, run `claude --plugin-dir ./plugins/nostr-vpn` from this checkout.

## Grok Build and Grok Bot

Grok Build supports Claude-compatible plugins. From this checkout:

```sh
grok --plugin-dir ./plugins/nostr-vpn
```

Use its plugin/skills menu to select the workflow. Grok Bot is a separate
surface: give it the [workflow guide](https://github.com/mmalmi/nostr-vpn/blob/master/docs/agents.md) and ask it to perform the task
with its terminal, then save the verified procedure as a skill. This repository
is not automatically listed in Grok Bot's Connect apps directory.

## Hermes Agent

Hermes supports the root `plugin.json` Agent Plugins v1 package directly:

```sh
hermes plugins install mmalmi/nostr-vpn/plugins/nostr-vpn --no-enable
hermes plugins enable nostr-vpn
```

Start a new session and ask Hermes to load `nostr-vpn:nostr-vpn` using
`skills_list` and `skill_view`. No Hermes-specific Python extension or MCP
server is needed. The terminal environment must have the CLI and persistent
storage for its identity. Plugin updates must not replace that identity.

## Other Agent Skills clients

Install `plugins/nostr-vpn/skills/nostr-vpn` from the repository using your client's skill installer. Keep the whole
folder together. The [skill](skills/nostr-vpn/SKILL.md) is the canonical
workflow; platform manifests all refer to it.

## What it accesses

When asked to connect, the agent invokes nvpn with a chosen persistent local
configuration and connects to configured relays and peers. Starting a VPN changes
host interfaces and routes and requires operating-system privileges. Signed
enrollment requires an administrator; the plugin grants no network access by
itself. The CLI manages keys; the skill does not read or expose key sidecars.
The daemon remains running until stopped. No telemetry is added.

## Package and validate

From a committed checkout, create a small distribution ZIP without app sources,
build artifacts, identities, or configuration:

```sh
git archive --format=zip --output=nostr-vpn-plugin.zip HEAD:plugins/nostr-vpn
claude plugin validate plugins/nostr-vpn
```

Keep generated ZIPs outside commits. Validate an extracted ZIP too, and run the
workflow with a fresh test identity before submitting to a directory. Public
catalogs have separate review requirements; a valid package is not a listing.

Packaging references: [OpenAI](https://developers.openai.com/plugins/build/plugins),
[desktop execution](https://developers.openai.com/plugins/deploy/desktop-only),
[Claude](https://code.claude.com/docs/en/plugins/publish),
[Grok](https://docs.x.ai/build/features/skills-plugins-marketplaces), and
[Hermes](https://hermes-agent.nousresearch.com/docs/developer-guide/plugins).
