//! `routing` submodule: file IO, source download, and geoip/protobuf parsing.
//!
//! Pure helpers split out of the oversized `routing.rs`. None of these touch
//! `RoutingInner`; they operate only on paths, bytes, and the rule/source value
//! types re-exported from the parent module via `use super::*`.

use std::{
    fs,
    io::{self, Write},
    net::IpAddr,
    path::{Path, PathBuf},
    process::Command,
    time::SystemTime,
};

use ipnet::IpNet;

use super::*;

pub(super) fn parse_text_rules(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|line| {
            let line = line.split('#').next().unwrap_or_default().trim();
            if line.is_empty() { None } else { Some(line.to_owned()) }
        })
        .collect()
}

pub(super) fn read_rule_lists(dir: &Path) -> io::Result<RuleLists> {
    Ok(RuleLists {
        direct_ip: read_lines(dir.join(DIRECT_IP_FILE))?,
        direct_domain: read_lines(dir.join(DIRECT_DOMAIN_FILE))?,
        proxy_ip: read_lines(dir.join(PROXY_IP_FILE))?,
        proxy_domain: read_lines(dir.join(PROXY_DOMAIN_FILE))?,
    })
}

pub(super) fn read_temporary_rule_lists(dir: &Path) -> io::Result<RuleLists> {
    Ok(RuleLists {
        direct_ip: read_temp_lines(dir, TEMP_DIRECT_IP_FILE)?,
        direct_domain: read_temp_lines(dir, TEMP_DIRECT_DOMAIN_FILE)?,
        proxy_ip: read_temp_lines(dir, TEMP_PROXY_IP_FILE)?,
        proxy_domain: read_temp_lines(dir, TEMP_PROXY_DOMAIN_FILE)?,
    })
}

pub(super) fn write_temporary_rule_lists(dir: &Path, lists: &RuleLists) -> io::Result<()> {
    fs::create_dir_all(dir.join(TEMP_DIR))?;
    write_lines_atomic(temp_file_path(dir, TEMP_DIRECT_IP_FILE), &lists.direct_ip)?;
    write_lines_atomic(temp_file_path(dir, TEMP_DIRECT_DOMAIN_FILE), &lists.direct_domain)?;
    write_lines_atomic(temp_file_path(dir, TEMP_PROXY_IP_FILE), &lists.proxy_ip)?;
    write_lines_atomic(temp_file_path(dir, TEMP_PROXY_DOMAIN_FILE), &lists.proxy_domain)?;
    Ok(())
}

pub(super) fn temporary_files_fingerprint(dir: &Path) -> io::Result<Vec<Option<u64>>> {
    [
        TEMP_DIRECT_IP_FILE,
        TEMP_DIRECT_DOMAIN_FILE,
        TEMP_PROXY_IP_FILE,
        TEMP_PROXY_DOMAIN_FILE,
    ]
    .into_iter()
    .map(|file_name| file_fingerprint(&temp_file_path(dir, file_name)))
    .collect()
}

pub(super) fn file_fingerprint(path: &Path) -> io::Result<Option<u64>> {
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    Ok(Some(hash))
}

pub(super) fn read_temp_lines(dir: &Path, file_name: &str) -> io::Result<Vec<String>> {
    read_lines(temp_file_path(dir, file_name))
}

pub(super) fn temp_file_path(dir: &Path, file_name: &str) -> PathBuf {
    dir.join(TEMP_DIR).join(file_name)
}

pub(super) fn sanitize_sources(sources: RoutingSources) -> RoutingSources {
    let mut sources = sources;
    dedup_ip_list(&mut sources.client_global_proxy_ips);
    dedup_ip_list(&mut sources.client_direct_ips);
    sources
}

pub(super) fn dedup_ip_list(values: &mut Vec<IpAddr>) {
    let mut seen = HashSet::new();
    values.retain(|ip| seen.insert(*ip));
}

pub(super) fn read_lines(path: impl AsRef<Path>) -> io::Result<Vec<String>> {
    let path = path.as_ref();
    if !path.exists() {
        return Ok(Vec::new());
    }
    Ok(parse_text_rules(&fs::read_to_string(path)?))
}

pub(super) fn append_lines(path: &Path, lines: &[String]) -> io::Result<()> {
    if lines.is_empty() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut file = fs::OpenOptions::new().create(true).append(true).open(path)?;
    for line in lines {
        writeln!(file, "{line}")?;
    }
    Ok(())
}

pub(super) fn write_lines_atomic(path: impl AsRef<Path>, lines: &[String]) -> io::Result<()> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("tmp");
    {
        let mut file = fs::File::create(&tmp)?;
        for line in lines {
            writeln!(file, "{line}")?;
        }
    }
    fs::rename(tmp, path)
}

pub(super) fn ensure_file(path: impl AsRef<Path>) -> io::Result<()> {
    let path = path.as_ref();
    if !path.exists() {
        write_lines_atomic(path, &[])?;
    }
    Ok(())
}

pub(super) fn file_modified(path: &Path) -> io::Result<Option<SystemTime>> {
    match fs::metadata(path) {
        Ok(metadata) => metadata.modified().map(Some),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub(super) struct DownloadedSource {
    pub(super) bytes: Vec<u8>,
    pub(super) display_name: String,
    pub(super) status: DownloadedSourceStatus,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DownloadedSourceStatus {
    Downloaded,
    FallbackCache,
    LocalFile,
}

pub(super) async fn download_source(source: &str, cache_dir: &Path) -> io::Result<DownloadedSource> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let source = source.to_owned();
        let cache_dir = cache_dir.to_owned();
        tokio::task::spawn_blocking(move || {
            let display_name = source_cache_name(&source);
            let cache_path = cached_source_path(&source, &cache_dir);
            fs::create_dir_all(&cache_dir)?;
            let temp_dir = cache_dir.join(SOURCE_TEMP_DIR);
            fs::create_dir_all(&temp_dir)?;
            for (cmd, args) in [
                ("uclient-fetch", vec!["-q", "-O", "-", &source]),
                ("wget", vec!["-qO-", &source]),
                ("curl", vec!["-fsSL", &source]),
            ] {
                match Command::new(cmd).args(args).output() {
                    Ok(out) if out.status.success() && !out.stdout.is_empty() => {
                        write_downloaded_source_atomic(&cache_path, &temp_dir, &out.stdout)?;
                        return Ok(DownloadedSource {
                            bytes: out.stdout,
                            display_name,
                            status: DownloadedSourceStatus::Downloaded,
                        });
                    }
                    _ => continue,
                }
            }
            if let Some(bytes) = read_non_empty_file(&cache_path)? {
                return Ok(DownloadedSource {
                    bytes,
                    display_name,
                    status: DownloadedSourceStatus::FallbackCache,
                });
            }
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "download failed or returned empty output, and no existing source file is available",
            ))
        })
        .await
        .map_err(|err| io::Error::other(err.to_string()))?
    } else {
        Ok(DownloadedSource {
            bytes: fs::read(source)?,
            display_name: source_progress_name(source),
            status: DownloadedSourceStatus::LocalFile,
        })
    }
}

pub(super) fn cached_source_path(source: &str, cache_dir: &Path) -> PathBuf {
    cache_dir.join(source_cache_name(source))
}

pub(super) fn write_downloaded_source_atomic(path: &Path, temp_dir: &Path, bytes: &[u8]) -> io::Result<()> {
    fs::create_dir_all(temp_dir)?;
    let file_name = path.file_name().unwrap_or_else(|| std::ffi::OsStr::new("source.dat"));
    let tmp = temp_dir.join(file_name);
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)
}

pub(super) fn source_progress_name(source: &str) -> String {
    if source.starts_with("http://") || source.starts_with("https://") {
        source_cache_name(source)
    } else {
        Path::new(source)
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or(source)
            .to_owned()
    }
}

pub(super) fn source_cache_name(source: &str) -> String {
    let source = source
        .split('#')
        .next()
        .unwrap_or(source)
        .split('?')
        .next()
        .unwrap_or(source)
        .trim_end_matches('/');
    let name = source
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("source.dat");
    let name = name
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '-' | '_') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    if name.is_empty() { "source.dat".to_owned() } else { name }
}

pub(super) fn read_non_empty_file(path: &Path) -> io::Result<Option<Vec<u8>>> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.len() > 0 => fs::read(path).map(Some),
        Ok(_) => Ok(None),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub(super) fn read_geoip_cn_nets(path: &Path) -> io::Result<Vec<IpNet>> {
    match fs::read(path) {
        Ok(bytes) => parse_geoip_cn_nets(&bytes),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

pub(super) fn parse_geoip_cn_nets(bytes: &[u8]) -> io::Result<Vec<IpNet>> {
    let entries = read_len_fields(bytes, 1)?;
    if entries.is_empty() {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "empty geoip.dat"));
    }
    let mut nets = Vec::new();
    for entry in entries {
        let country = read_string_fields(entry, 1)
            .into_iter()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if country != "cn" {
            continue;
        }
        for cidr in read_len_fields(entry, 2)? {
            let ip = read_bytes_fields(cidr, 1).into_iter().next().unwrap_or_default();
            let prefix = read_varint_fields(cidr, 2).into_iter().next().unwrap_or(0);
            let ip = match ip.len() {
                4 => IpAddr::from([ip[0], ip[1], ip[2], ip[3]]),
                16 => {
                    let mut b = [0u8; 16];
                    b.copy_from_slice(&ip);
                    IpAddr::from(b)
                }
                _ => continue,
            };
            if let Some(net) = parse_ip_net(&format!("{ip}/{prefix}")) {
                nets.push(net);
            }
        }
    }
    nets.sort_unstable_by_key(ToString::to_string);
    nets.dedup();
    Ok(nets)
}

pub(super) fn read_len_fields(mut bytes: &[u8], field: u64) -> io::Result<Vec<&[u8]>> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let key = read_varint(&mut bytes)?;
        let number = key >> 3;
        let wire = key & 0x07;
        match wire {
            0 => {
                let _ = read_varint(&mut bytes)?;
            }
            2 => {
                let len = read_varint(&mut bytes)? as usize;
                if bytes.len() < len {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "protobuf field length"));
                }
                let (value, rest) = bytes.split_at(len);
                if number == field {
                    out.push(value);
                }
                bytes = rest;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported protobuf wire type",
                ));
            }
        }
    }
    Ok(out)
}

pub(super) fn read_bytes_fields(bytes: &[u8], field: u64) -> Vec<Vec<u8>> {
    read_len_fields(bytes, field)
        .unwrap_or_default()
        .into_iter()
        .map(ToOwned::to_owned)
        .collect()
}

pub(super) fn read_string_fields(bytes: &[u8], field: u64) -> Vec<String> {
    read_bytes_fields(bytes, field)
        .into_iter()
        .filter_map(|v| String::from_utf8(v).ok())
        .collect()
}

pub(super) fn read_varint_fields(mut bytes: &[u8], field: u64) -> Vec<u64> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let Ok(key) = read_varint(&mut bytes) else {
            break;
        };
        let number = key >> 3;
        let wire = key & 0x07;
        match wire {
            0 => {
                if let Ok(value) = read_varint(&mut bytes)
                    && number == field
                {
                    out.push(value);
                }
            }
            2 => {
                let Ok(len) = read_varint(&mut bytes) else {
                    break;
                };
                let len = len as usize;
                if bytes.len() < len {
                    break;
                }
                bytes = &bytes[len..];
            }
            _ => break,
        }
    }
    out
}

pub(super) fn read_varint(bytes: &mut &[u8]) -> io::Result<u64> {
    let mut value = 0u64;
    for shift in (0..64).step_by(7) {
        let Some((&byte, rest)) = bytes.split_first() else {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "protobuf varint"));
        };
        *bytes = rest;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(io::Error::new(io::ErrorKind::InvalidData, "protobuf varint too long"))
}

/// Rewrite `data/futu_ip.txt` as the deduped union of its current contents and
/// `data/temp/proxy_ip.temp` (into which the Futu learner has just appended the
/// new destination). Tokens are canonicalised so a bare IP and its `/32` (or v6
/// `/128`) collapse to one entry; the result is sorted and written atomically.
/// Best-effort: the caller logs and ignores failures.
pub(super) fn rewrite_futu_ip_file(rules_dir: &Path) -> io::Result<()> {
    let futu_path = rules_dir.join(FUTU_IP_FILE);
    let temp_proxy_path = temp_file_path(rules_dir, TEMP_PROXY_IP_FILE);

    let mut canonical: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for path in [&futu_path, &temp_proxy_path] {
        // Missing/unreadable sources contribute nothing (e.g. first run before
        // futu_ip.txt exists).
        for line in read_lines(path).unwrap_or_default() {
            if let Some(value) = canonical_ip_or_cidr(&line) {
                canonical.insert(value);
            }
        }
    }
    let lines: Vec<String> = canonical.into_iter().collect();
    write_lines_atomic(&futu_path, &lines)
}

/// Canonicalise a rule line (which may carry a trailing domain annotation) to a
/// bare IP/CIDR string — a host address for `/32`/`/128`, the network form
/// otherwise — so `1.2.3.4` and `1.2.3.4/32` dedup to one entry. `None` if the
/// line has no parseable IP/CIDR. (`parse_ip_net` extracts the first token via
/// `ip_rule_value` and accepts both bare IPs and CIDRs.)
fn canonical_ip_or_cidr(line: &str) -> Option<String> {
    parse_ip_net(line).map(|net| display_ip_net(&net))
}

