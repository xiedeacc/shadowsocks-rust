Route rule generation uses only two downloaded source files:

- `data/source/geoip.dat`
- `data/source/gfw.txt`

`geoip.dat` is parsed in memory. CN CIDRs are written to `direct_ip.txt`.
`gfw.txt` is parsed as bypass-domain rules and written to `bypass_domain.txt`.

`direct_domain.txt` is preserved as a local rule file. It is not generated from
downloaded source lists. `bypass_ip.txt` is preserved as the runtime learned IP
file populated from remote DNS answers for bypass domains. Runtime learned rows
use `IP_OR_CIDR domain`, for example `142.250.72.14 www.google.com`; old
one-column IP/CIDR rows remain valid.

Temporary admin rules are persisted in:

- `direct_ip.temp`
- `direct_domain.temp`
- `bypass_ip.temp`
- `bypass_domain.temp`

Temporary rules are loaded on startup and have priority over persistent files.
When a direct and bypass temporary rule both match, direct wins and a conflict is
recorded.

Downloaded URL sources are cached for one week. Refresh downloads first into
`data/source/temp`; only a successful non-empty download replaces the current
source file. A weekly background update re-downloads stale sources and reindexes
the rule files.

Conflicts shown in the admin route page are derived from current in-memory
indexes and refreshed when the relevant files change:

- `bypass_ip.txt` overlapping CN ranges from `geoip.dat`
- `bypass_ip.txt` overlapping `direct_ip.txt`
- `bypass_domain.txt` overlapping `direct_domain.txt`

IP conflict checks handle both exact IPs and CIDR overlaps. Multi-label domain
rules match themselves and subdomains. Single-label domain rules are exact-only,
so `cn` does not match every `.cn` domain. Domain matching and domain conflict
checks support `*` wildcard patterns in both direct and bypass domain files.

For persistent domains, direct rules have priority over bypass rules when both
match. For example, `www.google.com` in `direct_domain.txt` wins over
`*.google.com` in `bypass_domain.txt`, and the overlap is still displayed in
Domain Conflicts.

The admin Connections page can record rows to `record.txt`. Starting a record
session truncates the file and subsequent connection refreshes append newly seen
rows as JSON lines.
