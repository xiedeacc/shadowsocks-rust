# Route Rule Generation

This document describes how the web routing admin generates these persistent files:

- `direct_domain.txt`
- `bypass_domain.txt`
- `direct_ip.txt`
- `bypass_ip.txt`

All generated files live in the configured data directory, normally `/usr/local/shadowsocks/data`.
Downloaded source files are cached under `data/source`. A download is first written to
`data/source/temp/<file>` and only replaces `data/source/<file>` after the download succeeds.

## Manual Rules

`manual_domain.txt` and `manual_ip.txt` accept only two decisions:

- `direct`
- `bypass`

Examples:

```text
example.com direct
blocked.example bypass
1.2.3.0/24 direct
8.8.8.8/32 bypass
```

Manual rules are used only while generating the persistent rule files. They are not checked directly
by runtime routing. This means `manual_domain.txt` wins over `apple-cn.txt`, `google-cn.txt`,
`gfw.txt`, and `china-list.txt` during generation, and its result is materialized into the generated
files.

Temporary rules configured in the web UI are runtime-only rules. They only have priority over the
generated persistent files. Runtime priority is:

1. Temporary rules
2. Generated `direct_domain.txt`, `bypass_domain.txt`, `direct_ip.txt`, and `bypass_ip.txt`

## Domain Generation

Domain source priority is:

1. `manual_domain.txt`
2. `apple-cn.txt` and `google-cn.txt`
3. `gfw.txt`
4. `china-list.txt`

`apple-cn.txt`, `google-cn.txt`, and `china-list.txt` are direct-domain sources, but they do not have
the same priority. `apple-cn.txt` and `google-cn.txt` are higher priority than `gfw.txt`, while
`china-list.txt` is lower priority than `gfw.txt`.

`gfw.txt` is a bypass-domain source. Domains from this file are added to `bypass_domain.txt` unless
`manual_domain.txt`, `apple-cn.txt`, or `google-cn.txt` overrides it.

If a domain appears in `apple-cn.txt` or `google-cn.txt` and also in `gfw.txt`, direct wins. The
domain is automatically written to `manual_domain.txt` as `direct`, and one Domain Conflict is
recorded. The conflict sources include the direct source file, `gfw.txt`, and `manual_domain.txt`.

If a domain appears in `china-list.txt` and `gfw.txt` with no manual rule, `gfw.txt` wins and the
domain is written to `bypass_domain.txt`. A Domain Conflict is still recorded with `china-list.txt`
and `gfw.txt` as sources.

If `manual_domain.txt` conflicts with `gfw.txt`, the manual decision wins and a Domain Conflict is
recorded. If the manual entry was auto-created because a direct source conflicted with `gfw.txt`,
the conflict is still shown once, with all relevant sources.

`geosite.dat` is downloaded and cached only. It does not participate in generating
`direct_domain.txt`, `bypass_domain.txt`, `direct_ip.txt`, or `bypass_ip.txt`.

## IP Generation

`geoip.dat` is parsed by region. CIDRs in region `cn` are added to `direct_ip.txt`. Other regions are
added to `bypass_ip.txt`.

If a CIDR matches `manual_ip.txt`, the manual decision wins. For example, if `geoip.dat` marks a CIDR
as `cn` but `manual_ip.txt` says `bypass`, the CIDR is written to `bypass_ip.txt`.

## Conflict Lists

Domain Conflicts are recorded when one domain has both `direct` and `bypass` regions after applying
source metadata and manual metadata. The displayed Sources column lists the source files involved,
including `manual_domain.txt` when applicable.

IP Conflicts are recorded when one CIDR has multiple regions in `geoip.dat`, or when a `geoip.dat`
region conflicts with `manual_ip.txt`. The displayed Sources column lists `geoip.dat` and
`manual_ip.txt` when applicable.
