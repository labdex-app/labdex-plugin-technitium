# Technitium DNS

A [labdex](https://github.com/reykimedev/labdex) plugin. Keeps a Technitium zone in sync with the inventory, plus zone-wide records of your own (per-host records are on each host's DNS tab), and shows which records in the zone belong to a host.

**Version** 1.4 · **Works with** labdex >=1.3,<2 · **Plugin id** `technitium`

> [!WARNING]
> Built with AI, for home labs only: labdex and its plugins were written largely with an AI
> coding assistant (Claude), directed and reviewed by a human. They haven't had an independent
> security audit and may contain security problems. Run them on a trusted home network.

## Install

It ships with labdex: **Plugins › Marketplace**, then *Install* (nothing is downloaded). Updates arrive through the official Marketplace (signed with the labdex project key).

## Settings

| Setting | Notes |
| --- | --- |
| URL | e.g. https://dns.example.net:53443 |
| API token | Create a token for a user that may only edit this zone |
| Extra zones to read | Space separated, e.g. legacy.lan. Read for Import and the host panels, never written. Labdex's own zones (the domain and every network or host zone override) are synced automatically, each record into the closest zone that exists on the server. |
| Zone (before 0.5.3) | Old single-zone setting: read like an extra zone, and the base for custom record names. Leave empty. |
| TTL (seconds) |  |
| Verify TLS certificate |  |
| CA bundle path |  |
| Give public service names their own zone | A service marked public with a public name (photos.example.com) gets a zone of that exact name here, answering with the internal address; the rest of example.com still resolves outside |
| Delete records that left the inventory | Only records labdex created (comment "labdex") |
| Custom records | Name relative to the inventory domain (@ = the domain itself, a trailing dot = absolute, in any zone on the server). MX/SRV values: '10 mail.example.net', '0 5 443 target.example.net'. |

## Actions

- **Test connection** (run)
- **Sync records** (plan)
- **Import records into Discovery** (run): A/AAAA records pointing at addresses that aren't in the inventory show up as unknown addresses, with the record's name

## Releasing

Bump `version` in `plugin.yaml`, add a `## <version>` section to `CHANGELOG.md`, commit, then
`git tag v<version> && git push --tags`. The release workflow signs the plugin with the
`LABDEX_SIGNING_KEY` secret and attaches `technitium-<version>.zip` to a GitHub release.
