# Routing Logic Flow

This document describes the runtime route decision flow used by the redir and
admin routing state.

## Domain Decision

```mermaid
flowchart TD
    A[Domain query or connection target] --> B[Normalize domain]
    B --> C{Temporary data/temp/direct_domain.temp matches?}
    C -- yes --> D{Temporary data/temp/bypass_domain.temp also matches?}
    D -- yes --> E[Record Domain Conflict]
    E --> F[DIRECT wins]
    D -- no --> F
    C -- no --> G{Temporary data/temp/bypass_domain.temp matches?}
    G -- yes --> H[PROXY: use remote DNS, add resolved IP/domain rows to bypass_ip.txt]
    G -- no --> I{direct_domain.txt matches?}
    I -- yes --> J{bypass_domain.txt also matches?}
    J -- yes --> K[Record Domain Conflict]
    K --> L[DIRECT wins]
    J -- no --> L
    I -- no --> M{bypass_domain.txt matches?}
    M -- yes --> H
    M -- no --> N[No domain rule: fallback to DNS/ACL behavior]
```

Multi-label domain rules match themselves and subdomains, so `pki.goog` also
matches `c.pki.goog`. Single-label rules such as `cn` are exact-only, so they do
not match every `.cn` domain. Use `*` for explicit wildcard matching, for
example `*.google.com`. If a domain matches both direct and bypass domain rules,
the admin page shows a Domain Conflict and the direct rule wins. Example:
`www.google.com` in `direct_domain.txt` wins over `*.google.com` in
`bypass_domain.txt`.

## IP Decision

```mermaid
flowchart TD
    A[Destination IP] --> B{Temporary data/temp/direct_ip.temp matches?}
    B -- yes --> C{Temporary data/temp/bypass_ip.temp also matches?}
    C -- yes --> D[Record IP Conflict]
    D --> E[DIRECT wins]
    C -- no --> E
    B -- no --> F{Temporary data/temp/bypass_ip.temp matches?}
    F -- yes --> G[PROXY: nft sends traffic to sslocal transparent proxy]
    F -- no --> H{direct_ip.txt matches?}
    H -- yes --> I{bypass_ip.txt also matches?}
    I -- yes --> J[Record IP Conflict]
    J --> K[DIRECT wins]
    I -- no --> K
    H -- no --> L{bypass_ip.txt matches?}
    L -- yes --> G
    L -- no --> M[No IP rule: fallback to DNS/ACL behavior]
```

IP rules handle exact IPs and CIDRs. `direct_ip.txt` has priority over
`bypass_ip.txt`, including CIDR overlaps. `bypass_ip.txt` may include an
optional second domain column, stores one row per IP/CIDR, and routing uses the
first IP/CIDR column.

## Source Update And Reindex

```mermaid
flowchart TD
    A[Weekly timer or admin Generate/Download] --> B[Check source cache age]
    B --> C{geoip.dat or gfw.txt stale or missing?}
    C -- no --> D[Use existing data/source files]
    C -- yes --> E[Download to data/source/temp]
    E --> F{Download succeeded and size > 0?}
    F -- no --> G[Keep old source file]
    F -- yes --> H[Atomically replace data/source file]
    D --> I[Parse geoip.dat CN CIDRs in memory]
    H --> I
    I --> J[Write CN CIDRs to direct_ip.txt]
    J --> K[Parse gfw.txt]
    K --> L[Write bypass_domain.txt]
    L --> M[Preserve direct_domain.txt and bypass_ip.txt]
    M --> N[Rebuild in-memory indexes]
    N --> O[Refresh nft bypass set]
```

Only `geoip.dat` and `gfw.txt` are downloaded source files.

## Conflict Detection

```mermaid
flowchart TD
    A[Conflict API or source/file update] --> B[Check file mtimes]
    B --> C{direct/bypass files or geoip.dat changed?}
    C -- no --> D[Return current conflict ring]
    C -- yes --> E[Reload direct_ip.txt, bypass_ip.txt, direct_domain.txt, bypass_domain.txt]
    E --> F[Reparse CN CIDRs from geoip.dat if changed]
    F --> G[Rebuild indexes]
    G --> H[Detect IP overlaps: direct_ip.txt vs bypass_ip.txt]
    G --> I[Detect IP overlaps: geoip.dat CN vs bypass_ip.txt]
    G --> J[Detect domain overlaps: direct_domain.txt vs bypass_domain.txt]
    H --> K[Admin IP Conflicts and data/temp/ip_conflicts.jsonl]
    I --> K
    J --> L[Admin Domain Conflicts and data/temp/domain_conflicts.jsonl]
```

IP conflict checks use CIDR overlap and read the first IP/CIDR column from
`bypass_ip.txt`. Domain conflict checks use exact, subdomain, and wildcard
overlap matching. Single-label rules do not act as top-level-domain wildcards.

## Debug URL

```mermaid
flowchart TD
    A[Admin Debug URL] --> B[Normalize URL and host]
    B --> C[Run domain routing decision]
    C --> D[Check DNS cache before test]
    D --> E[Run curl -4 with timeout]
    E --> F[Collect DNS events since start time]
    F --> G[Collect resolved IPs]
    G --> H[Collect recent connections since start time]
    H --> I{Redir/TUN connection to resolved IP observed?}
    I --> J[Return route decision, DNS/cache status, resolved IPs, transparent proxy status, HTTP/curl result]
```

## Debug IP / CIDR

```mermaid
flowchart TD
    A[Admin Debug IP/CIDR] --> B[Parse exact IP or CIDR]
    B -- invalid --> C[Return validation error]
    B -- valid --> D[Check bypass_ip.txt entries]
    D --> E[CIDR overlap or exact containment]
    E --> F{Linux local-dns build?}
    F -- yes --> G[Check nft bypass set]
    F -- no --> H[Skip nft check]
    G --> I[Return file matches and nft matches]
    H --> I
```

## Connection Recording

When the admin Connections page Record checkbox is enabled, the server truncates
`data/record.txt` and starts a new record session. Each subsequent connections
API response appends newly seen connection rows as JSON lines. Turning Record off
stops writing; it does not clear the current file.

Rows with decision `observed` are kernel-observed connections from conntrack or
`/proc/net/*` that were not matched to an in-memory sslocal flow decision.
