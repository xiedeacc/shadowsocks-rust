Route rule generation uses only two downloaded source files:

- `data/source/geoip.dat`
- `data/source/gfw.txt`

`geoip.dat` is parsed in memory. CN CIDRs are written to `direct_ip.txt`.
`gfw.txt` is parsed as bypass-domain rules and written to `bypass_domain.txt`.

`direct_domain.txt` is preserved as a local rule file. It is not generated from
downloaded source lists. `bypass_ip.txt` is preserved as the runtime learned IP
file populated from remote DNS answers for bypass domains.

Downloaded URL sources are cached for one week. Refresh downloads first into
`data/source/temp`; only a successful non-empty download replaces the current
source file. A weekly background update re-downloads stale sources and reindexes
the rule files.

Conflicts shown in the admin route page are derived from current in-memory
indexes and refreshed when the relevant files change:

- `bypass_ip.txt` overlapping CN ranges from `geoip.dat`
- `bypass_ip.txt` overlapping `direct_ip.txt`
- `bypass_domain.txt` overlapping `direct_domain.txt`

IP conflict checks handle both exact IPs and CIDR overlaps. Domain matching and
domain conflict checks support `*` wildcard patterns in both direct and bypass
domain files.
