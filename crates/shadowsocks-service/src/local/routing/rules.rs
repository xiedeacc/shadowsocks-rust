//! `routing` submodule: rule compilation, IP/CIDR + domain matching, conflict
//! detection, and nft-route-index construction.
//!
//! Pure functions over the rule value types (split out of `routing.rs`); no
//! `RoutingInner` access. Parent types/helpers come in via `use super::*`.

use std::{collections::HashSet, io, net::IpAddr};

use ipnet::IpNet;

use super::*;

pub(super) fn rules_match_ip(rules: &[IpNet], ip: &IpAddr) -> bool {
    rules.iter().any(|net| net.contains(ip))
}

pub(super) fn ip_nets_overlap(left: &IpNet, right: &IpNet) -> bool {
    match (left, right) {
        (IpNet::V4(left), IpNet::V4(right)) => left.contains(&right.network()) || right.contains(&left.network()),
        (IpNet::V6(left), IpNet::V6(right)) => left.contains(&right.network()) || right.contains(&left.network()),
        _ => false,
    }
}

pub(super) fn ip_net_conflicts(direct: &[IpNet], proxy: &[IpNet]) -> Vec<String> {
    let mut direct_v4 = Vec::new();
    let mut direct_v6 = Vec::new();
    let mut proxy_v4 = Vec::new();
    let mut proxy_v6 = Vec::new();
    for net in direct {
        let range = ip_net_range(net);
        if range.is_v4 {
            direct_v4.push(range);
        } else {
            direct_v6.push(range);
        }
    }
    for net in proxy {
        let range = ip_net_range(net);
        if range.is_v4 {
            proxy_v4.push(range);
        } else {
            proxy_v6.push(range);
        }
    }

    let mut conflicts = ip_range_conflicts(direct_v4, proxy_v4);
    conflicts.extend(ip_range_conflicts(direct_v6, proxy_v6));
    conflicts.sort_unstable();
    conflicts.dedup();
    conflicts
}

#[derive(Clone, Debug)]
pub(super) struct IpRange {
    start: u128,
    end: u128,
    label: String,
    is_v4: bool,
}

pub(super) fn ip_net_range(net: &IpNet) -> IpRange {
    match net {
        IpNet::V4(net) => {
            let start = u32::from(net.network()) as u128;
            IpRange {
                start,
                end: ip_range_end(start, 32, net.prefix_len()),
                label: display_ip_net(&IpNet::V4(*net)),
                is_v4: true,
            }
        }
        IpNet::V6(net) => {
            let start = u128::from(net.network());
            IpRange {
                start,
                end: ip_range_end(start, 128, net.prefix_len()),
                label: display_ip_net(&IpNet::V6(*net)),
                is_v4: false,
            }
        }
    }
}

pub(super) fn ip_range_end(start: u128, bits: u8, prefix_len: u8) -> u128 {
    let host_bits = bits.saturating_sub(prefix_len);
    if host_bits == 0 {
        start
    } else if host_bits >= 128 {
        u128::MAX
    } else {
        start | ((1u128 << host_bits) - 1)
    }
}

/// Sorted, merged, non-overlapping `[start, end]` u128 ranges (v4 and v6 kept
/// separate) giving O(log n) CIDR membership. Behaviour-equivalent to
/// `nets.iter().any(|n| n.contains(ip))` but suitable for large sets — chiefly
/// the geoip-CN table (thousands of CIDRs) that the DNS learning path probes for
/// every newly learned proxy IP (audit #6). Rebuilt only when the source set
/// changes, so the per-IP probe on the hot path is a binary search, not a scan.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(super) struct CidrRanges {
    v4: Vec<(u128, u128)>,
    v6: Vec<(u128, u128)>,
}

impl CidrRanges {
    pub(super) fn build(nets: &[IpNet]) -> Self {
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for net in nets {
            let range = ip_net_range(net);
            if range.is_v4 {
                v4.push((range.start, range.end));
            } else {
                v6.push((range.start, range.end));
            }
        }
        Self {
            v4: merge_sorted_ranges(v4),
            v6: merge_sorted_ranges(v6),
        }
    }

    pub(super) fn contains(&self, ip: &IpAddr) -> bool {
        let (ranges, key) = match ip {
            IpAddr::V4(addr) => (&self.v4, u128::from(u32::from(*addr))),
            IpAddr::V6(addr) => (&self.v6, u128::from(*addr)),
        };
        // Ranges are sorted by start and non-overlapping, so the only candidate
        // that can contain `key` is the last range whose start <= key.
        let idx = ranges.partition_point(|&(start, _)| start <= key);
        idx > 0 && ranges[idx - 1].1 >= key
    }
}

/// Sort by start, then coalesce overlapping or adjacent ranges into a minimal
/// non-overlapping set (so `contains`'s binary search is valid).
fn merge_sorted_ranges(mut ranges: Vec<(u128, u128)>) -> Vec<(u128, u128)> {
    ranges.sort_unstable();
    let mut merged: Vec<(u128, u128)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1.saturating_add(1) => {
                if end > last.1 {
                    last.1 = end;
                }
            }
            _ => merged.push((start, end)),
        }
    }
    merged
}

pub(super) fn ip_range_conflicts(mut direct: Vec<IpRange>, mut proxy: Vec<IpRange>) -> Vec<String> {
    direct.sort_unstable_by_key(|range| (range.start, range.end));
    proxy.sort_unstable_by_key(|range| (range.start, range.end));

    let mut conflicts = Vec::new();
    let mut first_possible = 0usize;
    for direct in &direct {
        while first_possible < proxy.len() && proxy[first_possible].end < direct.start {
            first_possible += 1;
        }
        let mut idx = first_possible;
        while idx < proxy.len() && proxy[idx].start <= direct.end {
            if proxy[idx].end >= direct.start {
                conflicts.push(format_ip_conflict(&direct.label, &proxy[idx].label));
            }
            idx += 1;
        }
    }
    conflicts
}

pub(super) fn format_ip_conflict(direct: &str, proxy: &str) -> String {
    if direct == proxy {
        direct.to_owned()
    } else {
        format!("{direct} <-> {proxy}")
    }
}

pub(super) fn display_ip_net(net: &IpNet) -> String {
    match net {
        IpNet::V4(net) if net.prefix_len() == 32 => net.addr().to_string(),
        IpNet::V6(net) if net.prefix_len() == 128 => net.addr().to_string(),
        _ => net.to_string(),
    }
}

pub(super) fn compiled_rules_match_ip(exact: &HashSet<IpAddr>, nets: &[IpNet], ip: &IpAddr) -> bool {
    exact.contains(ip) || rules_match_ip(nets, ip)
}

pub(super) fn compiled_rules_match_ip_indexed(exact: &HashSet<IpAddr>, ranges: &CidrRanges, ip: &IpAddr) -> bool {
    exact.contains(ip) || ranges.contains(ip)
}

pub(super) fn rules_match_domain(rules: &CompiledDomainRules, domain: &str) -> bool {
    if rules.match_all || rules.exact.contains(domain) {
        return true;
    }
    let mut candidate = domain;
    loop {
        if candidate.contains('.') && rules.suffix.contains(candidate) {
            return true;
        }
        let Some((_, suffix)) = candidate.split_once('.') else {
            break;
        };
        candidate = suffix;
    }
    false
}

pub(super) fn domain_rule_conflicts(direct: &HashSet<String>, proxy: &HashSet<String>) -> Vec<String> {
    let mut conflicts = Vec::new();
    let direct_wildcards = direct.iter().filter(|rule| rule.contains('*')).collect::<Vec<_>>();
    let proxy_wildcards = proxy.iter().filter(|rule| rule.contains('*')).collect::<Vec<_>>();

    for direct in direct {
        if direct.contains('*') {
            continue;
        }
        for proxy_candidate in domain_match_candidates(direct) {
            if proxy.contains(&proxy_candidate) {
                conflicts.push(format_domain_conflict(direct, &proxy_candidate));
            }
        }
    }

    for proxy in proxy {
        if proxy.contains('*') {
            continue;
        }
        for direct_candidate in domain_match_candidates(proxy) {
            if direct.contains(&direct_candidate) {
                conflicts.push(format_domain_conflict(&direct_candidate, proxy));
            }
        }
    }

    for direct in &direct_wildcards {
        for proxy in proxy {
            if domain_rules_overlap(direct, proxy) {
                conflicts.push(format_domain_conflict(direct, proxy));
            }
        }
    }

    for proxy in &proxy_wildcards {
        for direct in direct {
            if direct.contains('*') {
                continue;
            }
            if domain_rules_overlap(direct, proxy) {
                conflicts.push(format_domain_conflict(direct, proxy));
            }
        }
    }

    conflicts.sort_unstable();
    conflicts.dedup();
    conflicts
}

pub(super) fn domain_match_candidates(domain: &str) -> Vec<String> {
    let mut candidates = vec![domain.to_owned()];
    for (idx, _) in domain.match_indices('.') {
        let suffix = &domain[idx + 1..];
        if suffix.contains('.') {
            candidates.push(suffix.to_owned());
        }
    }
    candidates
}

pub(super) fn format_domain_conflict(direct: &str, proxy: &str) -> String {
    if direct == proxy {
        direct.to_owned()
    } else {
        format!("{direct} <-> {proxy}")
    }
}

pub(super) fn domain_rules_overlap(left: &str, right: &str) -> bool {
    domain_matches_rule(left, right) || domain_matches_rule(right, left)
}

pub(super) fn domain_matches_rule(rule: &str, domain: &str) -> bool {
    if let Some(suffix_rule) = rule.strip_prefix("*.") {
        domain_matches_rule(suffix_rule, domain)
    } else if rule.contains('*') {
        false
    } else if !rule.contains('.') {
        domain == rule
    } else {
        domain == rule
            || (domain.len() > rule.len()
                && domain.ends_with(rule)
                && domain.as_bytes()[domain.len() - rule.len() - 1] == b'.')
    }
}

pub(super) fn compile_rules(raw: &RuleLists) -> io::Result<CompiledRules> {
    let (direct_ip, direct_ip_exact, _) = compile_ip_rules(&raw.direct_ip, false);
    let (proxy_ip, proxy_ip_exact, proxy_ip_domainless_exact) = compile_ip_rules(&raw.proxy_ip, true);
    let direct_ip_ranges = CidrRanges::build(&direct_ip);
    let proxy_ip_ranges = CidrRanges::build(&proxy_ip);
    Ok(CompiledRules {
        direct_ip,
        direct_ip_exact,
        direct_ip_ranges,
        direct_domain: compile_domain_rules(&raw.direct_domain)?,
        proxy_ip,
        proxy_ip_exact,
        proxy_ip_domainless_exact,
        proxy_ip_ranges,
        proxy_domain: compile_domain_rules(&raw.proxy_domain)?,
    })
}

pub(super) fn compile_ip_rules(
    lines: &[String],
    track_domainless_exact: bool,
) -> (Vec<IpNet>, HashSet<IpAddr>, HashSet<IpAddr>) {
    let mut cidrs = Vec::new();
    let mut exact = HashSet::new();
    let mut domainless_exact = HashSet::new();
    for line in lines {
        let Some(value) = ip_rule_value(line) else {
            continue;
        };
        let domainless = line.split_whitespace().nth(1).is_none();
        if let Ok(ip) = value.parse::<IpAddr>() {
            exact.insert(ip);
            if track_domainless_exact && domainless {
                domainless_exact.insert(ip);
            }
            continue;
        }
        let Ok(net) = value.parse::<IpNet>() else {
            continue;
        };
        if let Some(ip) = host_net_ip(&net) {
            exact.insert(ip);
            if track_domainless_exact && domainless {
                domainless_exact.insert(ip);
            }
        } else {
            cidrs.push(net);
        }
    }
    (cidrs, exact, domainless_exact)
}

pub(super) fn host_net_ip(net: &IpNet) -> Option<IpAddr> {
    match net {
        IpNet::V4(net) if net.prefix_len() == 32 => Some(IpAddr::V4(net.addr())),
        IpNet::V6(net) if net.prefix_len() == 128 => Some(IpAddr::V6(net.addr())),
        _ => None,
    }
}

pub(super) fn compiled_rule_nets_for_nft(exact: &HashSet<IpAddr>, cidrs: &[IpNet]) -> Vec<IpNet> {
    let mut nets = Vec::with_capacity(exact.len() + cidrs.len());
    nets.extend(exact.iter().copied().map(IpNet::from));
    nets.extend(cidrs.iter().copied());
    nets
}

pub(super) fn compiled_rule_net_count(exact: &HashSet<IpAddr>, cidrs: &[IpNet]) -> usize {
    exact.len() + cidrs.len()
}

pub(super) fn nft_route_index_from_nets(direct: &[IpNet], proxy: &[IpNet]) -> NftRouteIndex {
    let (direct_ip, direct_ip_exact) = nft_route_index_split_nets(direct);
    let (proxy_ip, proxy_ip_exact) = nft_route_index_split_nets(proxy);
    let direct_ip_ranges = CidrRanges::build(&direct_ip);
    let proxy_ip_ranges = CidrRanges::build(&proxy_ip);
    NftRouteIndex {
        direct_ip,
        direct_ip_exact,
        direct_ip_ranges,
        proxy_ip,
        proxy_ip_exact,
        proxy_ip_ranges,
    }
}

pub(super) fn nft_route_index_split_nets(nets: &[IpNet]) -> (Vec<IpNet>, HashSet<IpAddr>) {
    let mut cidrs = Vec::new();
    let mut exact = HashSet::new();
    for net in nets {
        if let Some(ip) = host_net_ip(net) {
            exact.insert(ip);
        } else {
            cidrs.push(*net);
        }
    }
    cidrs.sort_unstable();
    (cidrs, exact)
}

pub(super) fn nft_route_index_matches(index: &NftRouteIndex, decision: RouteDecision, ip: &IpAddr) -> bool {
    match decision {
        RouteDecision::Direct => compiled_rules_match_ip_indexed(&index.direct_ip_exact, &index.direct_ip_ranges, ip),
        RouteDecision::Proxy => compiled_rules_match_ip_indexed(&index.proxy_ip_exact, &index.proxy_ip_ranges, ip),
    }
}

pub(super) fn compile_domain_rules(lines: &[String]) -> io::Result<CompiledDomainRules> {
    let mut compiled = CompiledDomainRules::default();
    for line in lines {
        let rule = normalize_domain(line);
        if rule.is_empty() {
            continue;
        }
        compiled.raw.insert(rule.clone());
        if rule == "*" {
            compiled.match_all = true;
        } else if let Some(suffix) = rule.strip_prefix("*.") {
            if suffix.is_empty() || suffix.contains('*') || !suffix.contains('.') {
                return Err(invalid_domain_wildcard(&rule));
            }
            compiled.suffix.insert(suffix.to_owned());
        } else if rule.contains('*') {
            return Err(invalid_domain_wildcard(&rule));
        } else if rule.contains('.') {
            compiled.suffix.insert(rule);
        } else {
            compiled.exact.insert(rule);
        }
    }
    Ok(compiled)
}

pub(super) fn invalid_domain_wildcard(rule: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unsupported domain wildcard rule '{rule}'; only '*.domain.tld' wildcard form is supported"),
    )
}

pub(super) fn parse_ip_net(value: &str) -> Option<IpNet> {
    let value = ip_rule_value(value)?;
    if let Ok(net) = value.parse::<IpNet>() {
        return Some(net);
    }
    value.parse::<IpAddr>().ok().map(IpNet::from)
}

#[cfg(test)]
pub(super) fn parse_ip_addr(value: &str) -> Option<IpAddr> {
    ip_rule_value(value)?.parse::<IpAddr>().ok()
}

pub(super) fn ip_rule_value(value: &str) -> Option<&str> {
    value.split_whitespace().next().filter(|value| !value.is_empty())
}

pub(super) fn format_proxy_ip_domain_line(ip: &IpAddr, domain: &str) -> String {
    let domain = normalize_dns_domain(domain);
    if domain.is_empty() {
        ip.to_string()
    } else {
        format!("{ip} {domain}")
    }
}

pub(super) fn proxy_ip_line_exact_matches_ip(rule: &str, ip: &IpAddr) -> bool {
    let Some(value) = ip_rule_value(rule) else {
        return false;
    };
    if let Ok(rule_ip) = value.parse::<IpAddr>() {
        return rule_ip == *ip;
    }
    value
        .parse::<IpNet>()
        .ok()
        .and_then(|net| host_net_ip(&net))
        .is_some_and(|rule_ip| rule_ip == *ip)
}

pub(super) fn proxy_ip_line_domain(rule: &str) -> Option<String> {
    let domain = rule.split_whitespace().nth(1).map(normalize_dns_domain)?;
    (!domain.is_empty()).then_some(domain)
}
