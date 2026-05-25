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

Manual rules have the highest priority when they match a generated rule.

## Domain Generation

`apple-cn.txt`, `china-list.txt`, and `google-cn.txt` are direct-domain sources. Domains from these
files are added to `direct_domain.txt` unless a matching `manual_domain.txt` entry says `bypass`.
In that case the domain is written to `bypass_domain.txt` and a Domain Conflict is recorded with
the source file and `manual_domain.txt`.

`gfw.txt` is a bypass-domain source. Domains from this file are added to `bypass_domain.txt` unless
a higher-priority direct source or manual rule overrides it.

If a domain appears in both a direct-domain source and `gfw.txt`, direct wins. The domain is
automatically written to `manual_domain.txt` as `direct`, and one Domain Conflict is recorded. The
conflict sources include the direct source file, `gfw.txt`, and `manual_domain.txt`.

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
