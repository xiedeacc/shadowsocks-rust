# shadowsocks-rust 定制分支全面审计报告

- 分支：`config_dns`　基线（upstream merge-base）：`c6e6480`
- 审计日期：2026-06-16
- 审计范围：学习式代理 / 全局透明代理 / nft 路由 / DNS / admin 页面 / Futu SOCKS 学习器 / 部署脚本 / `routing.md`
- 方法：11 个子系统并行深读 + 对每条 high/critical 结论做对抗式复核（27 个 agent，约 600 次工具调用），并在 **tiger（192.168.2.126）本机** 与 **OpenWrt（192.168.2.1:10022）** 上做只读的实地验证与链路测试。
- 本报告仅做审计，**未改动任何代码**。文末给出按优先级排序的修复计划，待你 review 后再实施。

> 结论速览：**整体架构是安全且正确的**。核心安全约束（不影响 OpenWrt 自身可达性、单独 nft 表可原子拆除、无路由环、OpenWrt 自身可翻墙）在**正常运行与优雅退出路径下都满足**，实地验证全部通过。主要风险集中在三类：(1) **非优雅退出（panic / SIGKILL / procd 重启耗尽）下的 nft 残留**；(2) **req 2.3「指定源直连 + 国内 DNS」只实现了一半**；(3) **学习/Futu 热路径在全局写锁下做阻塞 IO + 全量重建**，以及 **admin 页面无鉴权/无 CSRF**。没有发现会「砖掉」路由器的问题——管理面（SSH/LAN）在所有故障路径下都保持可达。

---

## 0. 实地链路测试结果（需求 10）

在 tiger 本机直接对 OpenWrt 的 local DNS（`@192.168.2.1:53`，经 nft 重定向到 `:1053`）测时，并在 OpenWrt 上验证 nft set 命中与端到端可达。

### DNS 查询耗时（cold = 首次未命中，warm = 命中 cache）

| 域名 | 解析路径 | cold | warm（cache 命中） | 解析结果 | 是否触发 redir |
|---|---|---|---|---|---|
| `www.facebook.com` | 国外 DNS（经 SS 到 8.8.8.8） | — | **1–2 ms** | `57.144.150.1` | **是**（IP 在 `proxy4` set） |
| `www.wikipedia.org` | 国外 DNS | **121 ms** | **1 ms** | `103.102.166.224` | 是 |
| `www.baidu.com` | **国内 DNS（223.5.5.5）** | — | **1–2 ms** | `157.148.69.151/186`（中国 IP） | **否**（不在任何 set） |
| `www.taobao.com` | 国内 DNS | **17 ms** | **2 ms** | 中国 IP | 否 |
| `www.jd.com` | 国内 DNS | **12 ms** | **2 ms** | 中国 IP | 否 |

**验证结论：**
- `www.baidu.com` **走国内 DNS、解析到中国 IP、不在 nft set、不触发 redir、直连** —— 与需求预期完全一致 ✅
- `www.facebook.com` **走国外 DNS、解析 IP 进入 `proxy4` set、命中 redir 走代理** ✅
- **Cache 工作正常**：国外冷查询 121 ms → 命中后 1 ms；国内冷查询 12–17 ms → 命中后 2 ms。冷热差异显著，证明 cache 生效，且国内/国外按域名正确分流。

### 端到端可达性（在 OpenWrt 路由器自身执行 curl，验证需求 7）

| 目标 | 结果 |
|---|---|
| `https://www.google.com`（代理） | **HTTP 200, 0.22 s** |
| `https://www.facebook.com`（代理） | **HTTP 200, 0.87 s** |
| `https://www.baidu.com`（直连/国内） | **HTTP 200, 0.14 s** |

`proxy_local_output: true` 已开启，OpenWrt 自身经 output 链 redirect/tproxy 翻墙成功，**无环路**（server IP `54.179.191.126` 在所有链顶部 `return` 豁免）。

---

## 1. 实地环境快照（只读采集）

- 运行进程：`sslocal`（pid 21600）+ `xray-plugin`。监听：redir `:12345`(tcp/udp)、dns `:1053`(tcp/udp)、socks `:1080`/`:1081`、http `:1082`、**web admin `192.168.2.1:9090`**。
- nft 表：只有 `inet fw4`（OpenWrt 自带）与 **`inet ssrust_dns`（本项目唯一新增表）**。`fw4` 中检索 `1053/12345/0x5355/tproxy/ssrust/dport 53` —— **0 处引用，OpenWrt 防火墙完全未被改动** ✅
- `ssrust_dns` 含 8 个 set（`direct4/6`、`proxy4/6`、`client_proxy4/6`、`client_direct4/6`，均 `interval + auto-merge`，支持单 IP 与 CIDR）与 4 条 hook 链：`prerouting`/`output`（nat，TCP redirect + DNS 重定向）、`prerouting_tproxy`/`output_tproxy`（mangle，UDP tproxy）。
- set 规模：`proxy4`≈428、`direct4`≈30、`client_direct4`={192.168.2.216}、`client_proxy4`=空。
- 配置：`global_proxy:false`、`client_global_proxy_ips:[]`、`client_direct_ips:[192.168.2.216]`、国内 DNS `223.5.5.5`、国外 DNS `8.8.8.8`、server `54.179.191.126`、`dns_intercept_mode:"both"`、`proxy_local_output:true`。
- 数据文件行数：`proxy_domain.txt`=4245、`proxy_ip.txt`=481、`direct_domain.txt`=275、`direct_ip.txt`=0、`temp/proxy_domain.temp`=41、`temp/proxy_ip.temp`=17（Futu 学习，含腾讯云 CIDR）、`temp/direct_ip.temp`=15。

---

## 2. 架构与代码组织（便于后续定位）

| 关注点 | 代码位置 |
|---|---|
| nft 表/链/set 的创建、规则下发、拆除 | `crates/shadowsocks-service/src/local/dns/intercept_linux.rs`（1531 行，新增）。`NFT_TABLE="ssrust_dns"`。 |
| 路由决策 / 学习分类 / 内存索引 / 定期任务 | `crates/shadowsocks-service/src/local/routing.rs`（5942 行，新增） |
| DNS server（国内/国外分流、cache、HTTPS 预热） | `crates/shadowsocks-service/src/local/dns/server.rs`（+729） |
| 配置 schema（global_proxy / client IP 列表 / dns_intercept_mode） | `crates/shadowsocks-service/src/config.rs`（+281） |
| 装配与生命周期 | `crates/shadowsocks-service/src/local/mod.rs`（+512）、`src/service/local.rs` |
| admin 页面 | `crates/shadowsocks-service/src/local/web_admin/mod.rs`（2067 行，新增） |
| Futu 学习器 | `socks/server/socks5/tcprelay.rs`、`socks4/tcprelay.rs` → `routing.rs:add_temporary_proxy_ip` |
| 部署 / init | `deploy/scripts/deploy_openwrt.sh`、`deploy/openwrt/conf/shadowsocks-rust.init` |

**四种模式如何在 nft 中无冲突地组合（需求 2.4，决策路径全部在内核 set 查表，极短）：**
- `global_proxy=on`：主规则为 `daddr != @direct4 ... redirect/tproxy`（除直连 set 外全代理）。
- 学习模式（global off）：主规则 `daddr @proxy4 ... redirect/tproxy`。
- `client_direct` 源：链顶 `ip saddr @client_direct4 dport != 53 return`（即使 global on 也直连；**但 53 端口不豁免，DNS 仍进 local dns**）。
- `client_proxy` 源（仅 global off 时加）：`ip saddr @client_proxy4 dport != 53 redirect`。
- 防环：所有链顶部对 server IP `return`；`output_tproxy` 顶部 `meta mark 0x5355 return`；私网/保留段 `return`。

---

## 3. 安全性分析（需求 1、2、6、7）

### 3.1 不会砖掉路由器 ✅
LAN 段（`192.168.0.0/16`，含网关 `192.168.2.1` 与 SSH `10022`）、loopback、保留段都在 `FIXED_DIRECT4/6_RULES`，作为每条 redirect/tproxy 链**最顶部**的 `dport != 53 return` 规则发出（`add_fixed_direct_return_rules` 最先调用）。因此**任何故障状态下 SSH/LAN 管理面都保持可达**，不会出现需要重刷的「砖」。实地与代码均确认。

### 3.2 单表、可原子拆除 ✅
所有防火墙状态都在单独的 `inet ssrust_dns` 表内，拆除是一次 `nft delete table inet ssrust_dns`（外加 tproxy 的 `ip rule`/`route` 清理）。`fw4` 永不被触碰。没有做 `nft list ruleset` 快照/还原——**对单表方案而言这是正确取舍**（见 finding TD-7，info）。

### 3.3 拆除/还原的边界（核心风险，详见 Critical/High）
- **优雅退出（SIGTERM/SIGINT）**：`monitor/unix.rs` 捕获信号 → `LocalServer` 被 drop → `DnsInterceptGuard::drop`（`intercept_linux.rs:74-89`）删表+清 tproxy 路由。**完全正确还原** ✅
- **重建即自愈**：`setup_nft` 开头先 `delete table` 再 `add table`（`intercept_linux.rs:670-671`）。所以 procd 在崩溃后**重启进程**（前 5 次）会自动抹掉残留并重建，窗口仅为重启间隔（数秒）。
- **缺口**：`panic=abort`（release profile）与 SIGKILL **不触发 Drop**；且 procd `respawn 3600 5 5` **耗尽 5 次后不再重启**，此时残留表会**持续**把 DNS（及 global 模式下全部非直连流量）重定向到无人监听的端口 → **全 LAN DNS/上网中断**（但 SSH 仍可达，一条命令可恢复）。代码注释（`mod.rs:586`）已明确知晓该限制。详见 **C-1 / H-1**。

### 3.4 无路由环 ✅（一个潜在隐患）
实地 curl 验证 OpenWrt 自身经代理访问 google/facebook 正常，无环。防环机制完整：server IP `return`、`meta mark 0x5355 return`、私网 `return`。**唯一隐患**：server IP 的豁免规则在启动时**只解析一次**并写死为 IP 字面量；若 server 用**域名**配置且其 IP 变化（或启动时解析失败），sslocal 自身到新 server IP 的出站会命中 `daddr != @direct` 被 redirect 回自己 → **自环**。当前部署用的是 IP 字面量，故**隐患未触发**。详见 **H-5**。

### 3.5 OpenWrt 自身翻墙 ✅
`proxy_local_output:true` + output 链 redirect/tproxy + server 豁免，实地验证通过（见 §0）。

---

## 4. 需求符合度矩阵

| 需求 | 状态 | 说明 |
|---|---|---|
| 1.1 proxy_domain → 国外 DNS → IP 入 nft+proxy_ip.txt+cache | ✅ | 实地验证 facebook 链路正确 |
| 1.2 启动加载 proxy_ip(.txt/.temp) 入 nft，排除 direct_ip | ✅ | `sync_persistent_ip_rules_to_firewall`，`proxy4`=428 元素 |
| 1.3 `temp` 优先级高于 `txt` | ✅ | temporary 规则先于 persistent 匹配；每 2s 重载 temp |
| 1.4 内存索引 nft + ~5s 定期 diff，且不重复调用 api | ✅（有可优化点） | `NFT_INDEX_SYNC_INTERVAL=5s`；命中前查内存索引。但 diff 为「全表 dump+文本解析+全集合比较」，存在 TOCTOU（**ND-3/低**）与成本随表增长（**PERF**） |
| 1.5 非 proxy_domain → 国内 DNS + cache | ✅ | 实地验证 baidu 链路正确 |
| 1.6 国外解析到的 IP 若在 direct_ip → 不入 nft 但仍写 proxy_ip.txt | ✅ | 由 conflict/direct set 排除处理 |
| 1.7 国内解析到的 IP 若在 proxy_ip → 也要入 nft | ⚠️ 部分 | 启动时覆盖；**解析时（动态）不补加**（**LC-2/中**） |
| 1.8 单 IP 与 CIDR 都支持 | ✅ | set 为 `interval+auto-merge`；Futu temp 实地含单 IP 与 CIDR |
| 2.1 global_proxy 全局透明代理 | ✅ | `daddr != @direct4 redirect`，有专门单测 |
| 2.2 指定源强制走代理（即使 global off） | ✅ | `saddr @client_proxy4 redirect`（当前 list 为空，未激活，但代码路径正确） |
| 2.3 指定源强制直连（即使 global on），DNS 仍走 local dns 但用**国内**解析 | ⚠️ **半实现** | nft 侧：源直连 ✅，DNS 仍进 local dns ✅；但 **DNS server 选解析器只看域名、不看源 IP**，强制直连源查询 proxy_domain 时仍走**国外**解析（**H-3**） |
| 2.4 四模式无冲突、决策路径短 | ✅ | nft set 查表组合正确，详见 §2 |
| 3 admin 页面 | ✅ 功能在/⚠️ 安全 | 功能完整，但**无鉴权 + 无 CSRF**（**H-6/H-7**） |
| 4 Futu SOCKS 记录 dst IP 入 proxy_ip.temp | ✅ 功能在/⚠️ 性能 | 单 IP+CIDR 都记；但每个新 IP 触发全量重建（**H-4**），且 `proxy_ip.temp` 无上限（**UF-2/中**） |
| 6 不在 OpenWrt 内成环 | ✅ | 见 §3.4（域名 server 隐患 H-5） |
| 7 OpenWrt 自身翻墙 | ✅ | 实地 curl 验证 |
| 8 routing.md 评审 | ⚠️ | 多处与代码不符/缺失，见 §7 |

---

## 5. 详细 Findings（按严重度，已对抗式复核；标注复核后修正的严重度）

> 说明：每条均给出 `代码位置`、问题、证据、影响、以及复核结论。`复核` 一行是独立 agent 重读代码后的判定（confirmed/refuted）与严重度修正。

### 🔴 CRITICAL

**C-1　procd 重启耗尽后，残留 nft 重定向规则永久存在、无自动恢复**
- 位置：`deploy/openwrt/conf/shadowsocks-rust.init:61`（`respawn 3600 5 5`）+ `intercept_linux.rs:660-820`
- 问题：SIGKILL/panic 不触发 Drop；恢复完全依赖「下一次进程启动时 `setup_nft` 先删表」。procd 内部 respawn 直接 re-exec `command`（**不会**再跑 init 的 `start_service()`/`cleanup_firewall`），但**重启的 sslocal 自身会自愈**（`setup_nft:670` 删表重建）——所以前 5 次崩溃可自愈。真正的死局是**1 小时内崩溃 ≥5 次**后 procd 放弃重启：此时 `dport 53 redirect` 与（global 模式下）tproxy 规则仍指向死端口 → **全 LAN DNS（及 global 模式全 LAN 上网）持续中断**，直到人工 `nft delete table inet ssrust_dns` 或重启。崩溃循环（坏配置 / OOM）正是触发场景。
- 复核：**confirmed，维持 critical**。但有两点缓和：必须「崩溃循环 + 最后一次非优雅退出」同时满足；且**不砖机**——SSH/LuCI 仍可达，恢复仅需一条命令或重启，非重刷。
- 影响约束：(a)/(d)。

### 🟠 HIGH

**H-1　`panic=abort` 跳过 Drop 拆除，留下死端口重定向（LAN DNS/上网短时中断）**
- 位置：`Cargo.toml:54`（`panic="abort"`，注：upstream 基线即如此，非本分支引入）+ `intercept_linux.rs:74-89`
- 问题：release 用 `panic=abort`，任何 panic 直接 SIGABRT 不展开 → Drop 不执行 → 表残留。已确认存在真实 panic 点（如 `mod.rs:811` 的 `.expect("missing remote_dns_addr")`、`client_cache.rs` 的 `.expect`）。
- 复核：**confirmed，critical→high**。因为可恢复（init `cleanup_firewall` + `setup_nft` 自删 + procd respawn 自愈），且不砖机，中断窗口有界（数秒）。但确实违反「crash/kill 必须还原 pristine」的严格约束。

**H-2　proxy nft set / 内存索引 / `proxy_ip.txt` 无限增长、从不清理**
- 位置：`routing.rs:1112-1202`（add_dns_results）、`:1564`（启动回读）、`:4368-4398`（仅 cache 清理）
- 问题：每个国外解析 IP 都追加进 nft set + `proxy_ip.txt` + `proxy_ip_exact`，**永不删除**。DNS cache 的 TTL/容量淘汰**不会**调用 `remove_route_ips`，也不清理索引/文件。CDN IP 高频变动时，三者跨进程生命周期且**跨重启**单调增长（启动回读 `proxy_ip.txt`），并放大 5s 全表 dump 与每答案的 CIDR 线性扫描成本。
- 复核：**confirmed，high**。`:1229` 的 remove 分支并非死代码，但只在「域名翻转为 Direct」时触发，不是 GC。

**H-3　req 2.3 只实现一半：强制直连源未获得国内解析器**
- 位置：`dns/server.rs:1281-1409,1321,1345`、`routing.rs:1100-1103,2673-2703`、`intercept_linux.rs:880-899`
- 问题：nft 侧正确保留强制直连源的 53 端口进 local dns（`dport != 53 return` 不豁免 53）；但 DNS server 选「国内 vs 国外解析器」**只看 `route_domain(domain)`，完全忽略源 IP**（`source_ip` 一路传入却只用于审计日志 `record_dns`，`server.rs:1045` 处 `let _ = source_ip`）。后果：强制直连源查询任一 proxy_domain（或 global_proxy on 时查询任意域名）都走**国外**解析，拿到国外 IP 后又**直连**该 IP → 正是 req 2.3 想避免的「地理错配」。该结论在 dns-routing / config-wiring / dns-intercept 三个单元独立得出。
- 复核：**confirmed，high**。非安全/环路问题（连接仍直连、无泄漏），但明确的定制需求对整类客户端失效。

**H-4　Futu dst-IP 学习器在全局写锁下做阻塞 IO + 全量规则重建（每个新 IP，准 O(N²)，拖垮 DNS 热路径）**
- 位置：`routing.rs:1015-1056`；调用方 `socks5/tcprelay.rs:293-301`、`socks4/tcprelay.rs:162`
- 问题：每个新出现的 Futu 目的 IP（经 `tokio::spawn`）在持有 `inner.write().await` 期间：克隆整份 temporary RuleLists、归一化+排序全部 `proxy_ip`、**两次**全量 `compile_rules`、**同步**重写 4 个 temp 文件、读 4 文件做 FNV 指纹、`rebuild_conflicts`（含 ~19MB geoip 规模的冲突扫描），随后**不经 spawn_blocking**直接 `replace_route_nets`（flush+重灌整张 nft set）+ `flush_conntrack_dst`。这把同一把锁上的 DNS 解析（`add_dns_results`）与所有路由决策（`route_ip/route_domain`）全部串行阻塞。作者在 `proxy_ip.txt` 路径已用「锁外计算→spawn_blocking 写→30s 去抖」的正确范式，此处却没有。
- 复核：**confirmed，high**。去重保证「每个不同 IP 一次」，但 N 个不同 IP 的累计字节仍是 O(N²)。

**H-5　server 防环豁免仅启动时解析一次、从不刷新——域名型 server 在 IP 变化后会自环**
- 位置：`mod.rs:218,1086-1103`、`intercept_linux.rs:849-878,782-795`
- 问题：见 §3.4。TCP redirect 的 output 链**没有** `meta mark return` 的身份豁免（仅 UDP tproxy 链有），完全依赖写死的 server IP `return`。域名型 server（DDNS/failover/CDN）IP 轮换后即触发自环与代理全断。当前部署用 IP 字面量，**隐患未触发**。
- 复核：**confirmed，high**（latent）。建议：域名 server 时拒绝该组合，或周期性重解析进 `@server_exempt` set，或给 sslocal 出站打 `SO_MARK` + 链顶 `meta mark return`。

**H-6　admin 可绑 `0.0.0.0` 且默认无鉴权**
- 位置：`web_admin/mod.rs:355-372`、`config.rs:1580-1588`
- 问题：`WebAdminConfig::default().token=None` → `authorized()` 对每个请求直接 `return true`，唯一门槛是 `is_lan_admin_peer()`（仅校验源 IP 属私网）。**部署实测**：`192.168.2.1:9090` 无 token，`curl` 返回 200。任何 LAN 主机可无凭据改配置、重启服务、刷 nft set、改路由列表、读 DHCP 租约（MAC/主机名）。
- 复核：**confirmed，high**。实地确认 200 无鉴权。

**H-7　状态变更接口无 CSRF 保护（token 未设时）**
- 位置：`web_admin/mod.rs:128-352`
- 问题：所有 POST/PUT（重启、覆盖配置、改 temp-rules、改 DNS、刷规则…）无 `Origin/Referer/CORS/SameSite` 校验。`POST /api/restart` 无 body → 跨域 no-cors 简单请求即可重启服务；`read_json` 不校验 `Content-Type` → 用 `text/plain` 简单请求即可命中 `PUT /api/client-config` 改配置+重启（绕过本应触发的预检）。LAN 内任一浏览器访问恶意页即可被打。
- 复核：**confirmed，high**（盲打，CORS 阻止读响应）。

**H-8　`routing.md` 完全缺失「全局透明代理 + 按源 IP」整个特性（需求 2）**
- 位置：`routing.md:85-97,498-578`
- 问题：`global_proxy`、`client_global_proxy_ips`、`client_direct_ips`、`client_proxy4/6`、`client_direct4/6` 在 routing.md 中 **0 次出现**；nft 流程图未画 client set 与 saddr 规则；且 `routing.md:509` 仍称「direct set 当前不被代理规则使用」——这在 global 模式下**已是错误**（`intercept_linux.rs:841` 的 `daddr != @direct` 依赖它）。
- 复核：**confirmed，high**（文档缺口 + 一处事实性错误）。

### 🟡 MEDIUM（择要，共 30 条）

| ID | 标题 | 位置 | 要点 |
|---|---|---|---|
| LC-2 | 国内解析到的 IP 若在 proxy_ip，解析时不补加 nft（仅启动覆盖） | `routing.rs:1135-1141,3666-3668` | req 1.7 动态场景未覆盖 |
| LC-1 | 周期源刷新（7 天）只更新内存规则、不重灌 nft set | `routing.rs:1664-1675,1461-1476` | high→**medium**：自动刷新后基线增删需等重启才生效；web-admin 路径因重启而无碍 |
| SI-2 | 即便 IPv4-only server + `dns_ipv4_only`，仍装 IPv6 redirect/tproxy 规则 | `intercept_linux.rs:732-740,1059` | global 模式下可能黑洞 LAN IPv6 |
| DI-1 | DNS 重定向无存活性门控（high→**medium**） | `intercept_linux.rs:702-781` | 死端口黑洞；init 缺 `stop_service()`，纯 `stop` 不清表（真实缺陷） |
| DR-2 | cache 命中返回的记录 TTL 不重写（陈旧 TTL） | `routing.rs:2161-2234` | 客户端按错误 TTL 缓存 |
| DR-3 | 仅 Proxy cache 有刷新任务，Direct（国内）cache 从不刷新 | `routing.rs:2236-2256` | — |
| DR-4 | DNS cache 仅周六落盘（`DNS_CACHE_PERSIST_CHECK_INTERVAL=1h` + 周六判断） | `routing.rs:1376-1385` | 普通重启丢失新学映射 |
| CW-2 | 同一 IP 同时出现在 client_proxy 与 client_direct 时无校验/告警 | `routing.rs:4002-4012` | 模式 2/3 歧义 |
| CW-3 | 用户态 SOCKS/HTTP/tunnel 监听器完全忽略按源强制代理/直连（模式 2/3 仅 nft 生效） | `context.rs:187-202`,`auto_proxy_stream.rs:163` | 非透明入口不遵守源策略 |
| CW-4 | `dns_intercept_mode="firewall"` 但唯一 DNS 监听被 disable 时，残留重定向表 | `mod.rs:447-453` | DNS 可达性风险 |
| WA-4 | `read_json` 请求体无上限（内存 DoS） | `web_admin/mod.rs:1300-1308` | — |
| WA-5 | `is_lan_admin_peer` 信任 IPv4-mapped IPv6、漏 CGNAT 段 | `web_admin/mod.rs:854-869` | — |
| WA-6 | 任一 LAN peer 可触发服务重启 + 配置覆盖（重置 nft） | `web_admin/mod.rs:146-211` | 与 H-6/H-7 联动 |
| SI-3 | Futu `record_proxy_ip` 每个新 IP 触发全量 set 重建 + 文件重写 | `routing.rs:1015-1056` | 与 H-4 同源 |
| UF-2 | `proxy_ip.temp`（Futu）无上限/TTL/清理 | `routing.rs:1031,3955` | 无界增长 |
| TD-3 | firewall 模式启动不清理上次遗留的 iptables-fallback/孤儿 tproxy ip-rule | `mod.rs:591-597` | — |
| TD-4 | 启动时「装防火墙」与「DNS/redir 监听就绪」之间有短暂黑洞窗口 | `mod.rs:789-836` | 亚秒级、会自愈 |
| PERF-4 | `flush_conntrack_dst` 每 IP fork 一个 `conntrack -D` 子进程 | `intercept_linux.rs:207-234` | — |
| PERF-2 | 每条 DNS 答案在全局写锁下做索引的线性 CIDR 扫描 | `routing.rs:1123-1202` | — |

### 🟢 LOW / INFO（25 + 10 条，择要）
- `proxy_ip.txt` 去重按原始字符串，`1.2.3.4` 与 `1.2.3.4/32` 不合并（`routing.rs:3576`）。
- 容量淘汰是插入序（实为 FIFO 非 LRU）（`routing.rs:4436`）。
- TCP DNS 连接 10s 强制关闭，破坏连接复用（`server.rs:334`）。
- proxy 域名返回空/NODATA 无负缓存，每次重新经 SS 解析（`routing.rs:3748`）。
- UDP 代理发送失败静默丢包返回 Ok（`udp/association.rs:728`）。
- SOCKS5 UDP 路由决策忽略学习表，只查 fixed-direct（`udp/association.rs:580`，info）。
- 热路径上对每批 nft 候选 IP 打 WARN 级日志（`routing.rs:1203`）。
- 5s 索引同步用默认 Burst missed-tick，全表 dump 增大时可能连续补跑（`routing.rs:1517`）。
- `TD-7`（info）：未做 ruleset 快照/还原——**这是对单表方案的正确设计**，非缺陷。
- `routing.md` 多处与代码不符：固定直连段漏列 `224.0.0.0/4`、`240.0.0.0/4`；nft set 清单与「direct set 未用」陈述过期；内存索引/conntrack flush/Futu 学习器/init `cleanup_firewall` 均未文档化（H-8 之外的若干 doc 项，复核多为 low/info）。

---

## 6. 性能分析（需求 5）

**热路径（DNS 解析 + redir accept）当前的主要代价：**
1. **单把 `Arc<TokioRwLock<RoutingInner>>`**（`routing.rs:587`）串行化所有 DNS 与连接路由：每次 DNS 查询要顺序拿 4–6 次该锁（`server.rs:1321-1408`）。
2. **`rebuild_ip_conflicts` 在写锁内 + 同步落盘**（H-? 见下）：`add_dns_results` 对每个「有变化」的答案在持写锁期间跑 `ip_net_conflicts(geoip_cn≈数千 CIDR, proxy_ip)` 的排序扫描 + `persist_conflict_events` 同步写文件。页面加载时多新域名突发会反复触发。→ 这是 perf 单元独立确认的 **HIGH**（`routing.rs:1200-1202,2741-2769`）；建议从 DNS 路径移除（冲突只在规则文件变化时才会变）。
3. **Futu 学习路径**（H-4）：每个新 IP 全量重建 + flush 整张 set，是连接 churn 下全路由器 DNS/路由的主要 stall。
4. **nft 调用方式**：DNS 学习已批量化为单次 `nft -f -`（`intercept_linux.rs:169-191`，good）；但 `setup_nft` 启动期是 ~50+ 次独立 fork+exec（仅启动，可接受），`replace_route_nets` 每次全量 flush+灌（Futu/temp 路径热）。
5. **5s 索引同步**：`nft list table` 全量 dump + 文本解析 + 全集合相等比较，成本随 set 增长（与 H-2 增长叠加）。
6. **数据结构**：域名/IP 匹配存在线性扫描与每次 lookup 两次 String 分配（`routing.rs:3740`）；Futu 成员判断用 Vec 线性扫描而非 `HashSet`。

**正面**：DNS 答案的 nft 写入已 spawn_blocking + 批量 + 30s 去抖；cache 命中实测 1–2ms；set 用 `interval+auto-merge` 控制内核内存。

---

## 7. `routing.md` 评审（需求 8）

- **H-8**：缺整个 global/per-source 特性，且 `:509` 有事实性错误。
- 缺失：内存 nft 索引与 5s diff、conntrack flush 行为与对 `conntrack-tools` 的依赖、Futu 学习器、init `cleanup_firewall`（OpenWrt 上真正的 crash/kill 还原机制）、`DnsInterceptGuard::drop` 也清 tproxy 路由、`deploy_openwrt.sh --cleanup` 运维命令。
- 过期/不符：固定直连段漏 `224.0.0.0/4`、`240.0.0.0/4`；nft set 清单与实际 8 个 set 不符；`add_dns_results` Direct 分支描述与 global_proxy 代码路径矛盾。
- 复核普遍判定为文档类问题（H-8 为 high，其余多 medium/low），不影响运行，但会误导运维与二次开发。

---

## 8. 重构建议（需求 9，**仅描述，不实施**）

1. **拆 nft 生命周期与拆除为独立、信号安全的模块**：把 `nft delete table` + tproxy 清理收敛成一个幂等函数，并在 `panic hook` / `atexit` / `SIGABRT` 处都调用（解决 C-1/H-1 的根因——不要把安全关键的拆除只挂在 `Drop` 上）。
2. **决策层引入 `source_ip`**：把路由/解析决策从 `route_domain(domain)` 改为 `route(source_ip, addr, is_dns)`，让 H-3、CW-3 一并解决，并保持 O(1)（forced-direct/forced-proxy 用 `HashSet`）。
3. **学习/Futu 写入统一为「锁外计算 → 去抖批量 → spawn_blocking 增量 `add_route_ips`」**：复用已有的 `proxy_ip.txt` 去抖范式，消除 H-4/SI-3/PERF。把 `rebuild_ip_conflicts` 移出 DNS 热路径（只在规则文件变更时算）。
4. **`routing.rs`（5942 行）按职责拆分**：`lists`（加载/归一/去重）、`index`（内存 nft 索引 + diff）、`decision`（路由/解析决策）、`persist`（文件落盘+去抖）、`learn`（DNS/Futu 学习）。便于加锁粒度细化（按 set 分锁或用 `arc-swap` 读多写少）。
5. **admin 默认安全化**：非 loopback 监听时强制要求 token；变更类接口要求自定义头（强制 CORS 预检）+ 校验 `Origin`。
6. **保留索引为 CIDR 感知结构**（如 `IpNet` LPM / `ip_network_table`），替代线性扫描与全集合比较，让 5s diff 增量化。

> 重构务必保持目标功能不变，建议每步配单测 + 重新跑实地链路测试（§0）回归。

---

## 9. 建议修复计划（按优先级，待你 review 后实施）

### P0 —— 不破坏可达性的安全兜底（对应 C-1 / H-1）
- [ ] 在 `init` 增加 `stop_service()`，显式调用 `cleanup_firewall`（修复纯 `stop`/respawn 耗尽后残留）。
- [ ] 增加进程级兜底拆除：`panic hook` + `libc::atexit` + 捕获 `SIGTERM/SIGABRT/SIGSEGV` 时执行 `nft delete table inet ssrust_dns` 与 tproxy 清理；或为 release 改 `panic="unwind"` 并在顶层 catch 后拆除。
- [ ] 加一个极轻的 watchdog（procd `respawn` 给出 `term_timeout`，或一条 cron）：检测「无 sslocal 进程但 `ssrust_dns` 存在」时删表。
- [ ] 可选：让 :53 redirect「失败开放」——监听未就绪/不可达时降级为 `accept` 而非黑洞。
- *验收*：模拟 `kill -9` 与崩溃循环，确认 LAN DNS 在数秒内恢复且 SSH 始终可达。

### P1 —— 需求正确性
- [ ] **H-3 / req 2.3**：把 `source_ip` 接入 DNS 解析器选择——`client_direct_ips` 命中时强制走国内解析器与 Direct cache key，无视 proxy_domain / global_proxy。
- [ ] **LC-1 / LC-2**：`update_from_sources` 末尾补 `sync_persistent_ip_rules_to_firewall`；国内解析命中 proxy_ip 时动态补加 nft（req 1.7）。
- [ ] **H-5**：域名型 server 时，周期重解析进 `@server_exempt` set，或给 sslocal 出站打 `SO_MARK` + output 链顶 `meta mark return`；或在该组合下拒绝域名 server。

### P2 —— 性能
- [ ] **H-4 / SI-3 / PERF**：Futu 学习改为「去抖批量 + 锁外 spawn_blocking + 增量 `add_route_ips` + `HashSet` 成员判断」；DNS 热路径移除 `rebuild_ip_conflicts`。
- [ ] **H-2 / UF-2**：给 `proxy_ip.txt` / `proxy_ip.temp` / 内存索引加上限或 last-seen GC（配合 5s diff）。
- [ ] 索引改 CIDR 感知 LPM 结构，5s diff 增量化。

### P3 —— admin 安全
- [ ] **H-6 / H-7 / WA-***：非 loopback 监听强制 token；变更接口要求自定义头 + 校验 Origin；`read_json` 加体积上限。

### P4 —— 文档
- [ ] **H-8 + §7**：补 global/per-source 四模式、内存索引/5s diff、conntrack flush、Futu 学习器、init `cleanup_firewall` 与 `--cleanup`；修正固定直连段与「direct set 未用」陈述。

---

## 10. 附录：关键实地命令证据（摘录）

```
# 仅有 fw4 与 ssrust_dns 两张表；fw4 未被改动
$ nft list tables → inet fw4 / inet ssrust_dns
$ nft list table inet fw4 | grep -E '1053|12345|0x5355|tproxy|ssrust|dport 53' → (空)

# 命中验证
$ nft get element inet ssrust_dns proxy4 { 57.144.150.1 }  → 命中（facebook 走代理）
$ nft get element inet ssrust_dns proxy4 { 157.148.69.151 } → No such file（baidu 不走代理，直连）

# DNS 时延（tiger → @192.168.2.1）
www.wikipedia.org  COLD 121ms → WARM 1ms   (国外, cache 生效)
www.taobao.com     COLD 17ms  → WARM 2ms   (国内)
www.baidu.com      WARM 1-2ms 解析到 157.148.69.x (中国IP, 不触发 redir)

# OpenWrt 自身翻墙
router$ curl https://www.google.com   → 200 / 0.22s
router$ curl https://www.facebook.com → 200 / 0.87s
router$ curl https://www.baidu.com    → 200 / 0.14s
```

---

## 11. 实施状态（分支 `config_dns_refactor`，本次修复）

> 范围：按用户确认，**排除** H-2 / UF-2（无界增长 GC）与全部 admin 安全项（H-6/H-7/WA-*）；其余 H/M/L 修复 + 重构 1/2/3/4/6。
> 验证：原生 `cargo check` + `cargo test`（service lib **59/59 通过**）+ **aarch64-musl 交叉编译成功**（OpenWrt 目标二进制）。**未部署到路由器。**

| 编号 | 状态 | 落点 |
|---|---|---|
| C-1 procd 重启耗尽残留 | ✅ | init 新增 `stop_service()` + 独立看门狗实例 `ssrust-watchdog.sh`；启动无条件清理 |
| H-1 panic=abort 跳过 Drop | ✅ | `intercept_linux.rs` 新增 EmergencyTeardown 注册表 + panic hook（abort 前删表+清 tproxy） |
| TD-3/CW-4 启动残留清理 | ✅ | `cleanup_stale_nft_table` 改无条件执行 + 清残留 iptables 重定向 |
| TD-4/DI-1 启动黑洞窗口 | ✅ | 防火墙改在 DNS 监听**绑定后**安装 |
| H-3/CW-1 req 2.3 国内解析 | ✅ | `route_domain_for_source`（强制直连源→Direct/国内）；DNS server 接入 source_ip |
| CW-3 显式 SOCKS/HTTP 尊重按源 | ✅ | `source_is_forced_direct`，socks4/5 + http 接入（Futu 实例豁免） |
| LC-1 周期源刷新不同步 nft | ✅ | `update_from_sources` 末尾补 `sync_persistent_ip_rules_to_firewall` |
| LC-2 req 1.7 | ✅（既有覆盖） | 所有 proxy_ip 规则随 LC-1/启动/temp/Futu 同步入 nft set，CIDR 区间覆盖 |
| H-4/SI-3 Futu 学习热路径 | ✅ | O(1) 去重 + 锁外 spawn_blocking 写文件 + 增量 `add_route_ips`，去掉 geoip 冲突全扫与全量 nft 重建 |
| PERF-2 add_dns_results 冲突全扫 | ✅ | `index_new_proxy_ip_conflicts` 仅对新 IP 增量检测 |
| PERF-4 conntrack 每 IP fork | ✅（已 spawn_blocking） | 既有 add_dns_results 已 off-loop；Futu 路径合并入同一 spawn_blocking |
| DR-3 国内 cache 不刷新 | ✅ | 刷新任务新增 `refresh_direct_dns_cache`（域名解析器通用化） |
| DR-4 仅周六落盘 | ✅ | `dns_cache_persist_is_due` 改为「脏 + 每小时」 |
| DR-2 cache TTL 不递减 | ⚠️ 评估后不改 | 现行返回上游 TTL 已合理；递减到 ~1 会造成客户端紧密重查回环；DR-3 已保证新鲜度 |
| H-5 server 防环豁免会陈旧 | ✅ | sslocal 出站打专用 fwmark（默认 0x5356）+ OUTPUT 链 `meta mark return`（身份豁免，IP 轮换不失效） |
| SI-2 IPv4-only 下装 IPv6 规则 | ✅ | `dns_ipv4_only` 时不安装 IPv6 重定向/ tproxy 规则（避免 LAN IPv6 黑洞） |
| 低：热路径 WARN | ✅ | 降为 `debug!` |
| 低：5s diff missed-tick | ✅ | `MissedTickBehavior::Skip` |
| 低：UDP 静默丢包 / SOCKS5-UDP 学习表 / `/32` 去重 / FIFO | ⚠️ 评估后保留 | UDP 丢包重连是合理策略；其余为低值且行为敏感，已记录 |
| H-8 + 文档 | ✅ | `routing.md` 补全局/按源四模式、nft 8-set、修正「direct set 未用」与固定直连段、补拆除/看门狗/`--cleanup` |

**重构**：
- #1（nft 生命周期/信号安全拆除）、#2（决策层接入 source_ip）、#3（学习写入去抖+增量+锁外）已随上述修复落地。
- #4（拆分 `routing.rs`）：已将单文件拆为 `routing.rs` + `routing/{tests,fileio,rules}.rs`，从 6060 行降到 **3822 行（−37%）**，行为保持不变（纯搬移），`cargo test` 59/59 通过 + aarch64-musl 交叉编译通过。`fileio`=文件 IO/源下载/geoip 解析，`rules`=规则编译/IP+域名匹配/冲突检测，`tests`=单测。剩余约 3800 行（`impl RoutingState` 主体 + 决策/学习/dns-cache 状态函数）与 RoutingInner 耦合更紧，建议作为后续增量步骤继续拆（decision/learn/index/persist）。
- #6（CIDR LPM 索引）为行为相邻的性能改造，按约定**推迟到路由器实地验证（A）之后**再做。

*（第 0–10 节为原始审计；以上为实施记录。本次仅在分支 `config_dns_refactor` 改代码，未部署。）*
