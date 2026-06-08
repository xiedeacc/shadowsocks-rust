# Recent Connections Plan

## 目标语义

- `Recent Connections` 不再展示 `proxy` / `observed`。
- 可展示的 `ConnectionDecision` 收敛为：
  - `direct`
  - `socks5_proxy`
  - `http_proxy`
  - `redir`
  - `tun`
- `Direct` 表示系统快照中未命中 socks/http/redir/tun 标注的普通连接。
- `Proxy` 只保留为路由/DNS 决策语义，不作为连接展示类型。

## 固定 Direct 例外网段

- 以下地址始终按 Direct 处理，适用于 socks/http、redir、tun 入口：
  - `0.0.0.0/8`
  - `10.0.0.0/8`
  - `100.64.0.0/10`
  - `127.0.0.0/8`
  - `169.254.0.0/16`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
  - `198.18.0.0/15`
  - `::/128`
  - `::1/128`
  - `fc00::/7`
  - `fe80::/10`
  - `ff00::/8`
- 固定 Direct 例外网段是独立保护规则，不依赖旧 ACL bypass 逻辑。

## SOCKS/HTTP 出站行为

- socks/http 入口收到请求后，默认通过 SS server 建立连接。
- socks/http 入口目标命中私有、本地、链路本地、组播或保留网段时，仍然走 Direct。
- 不再让 socks/http 入口根据 routing/ACL 走 Direct；上述固定 Direct 例外是独立保护规则。
- 旧 ACL bypass 逻辑不删除、不重构，只是不用于 socks/http 入口的出站选择。
- Recent Connections:
  - SOCKS5 入口记录 `socks5_proxy`
  - HTTP 入口记录 `http_proxy`
  - socks/http 命中固定 Direct 例外网段时记录 `direct`

## redir/tun 行为

- redir/tun 入口保持现有透明代理逻辑。
- Linux nftables 透明代理规则同时支持 `redirect` 和 `tproxy` 两种机制：
  - `redirect` 属于 NAT/REDIRECT 路径，当前 Linux firewall 自动安装的 TCP Proxy IP 规则使用 `redirect to :redir_port`。
  - `tproxy` 属于透明代理路径，通常配合 mark、policy routing 和 `IP_TRANSPARENT`，可用于 TCP/UDP；Linux redir UDP 默认使用 `tproxy`。
- 无论底层使用 `redirect` 还是 `tproxy`，redir 应用层事件必须记录用户原始目标，例如 `119.119.119.119:443`，不能记录本地 redir 监听地址或监听端口。
- redir/tun 目标命中固定 Direct 例外网段时，也必须走 Direct。
- Linux redir/firewall 模式下，固定 Direct 例外网段不应加入 nft Proxy set；如果已存在，应从 nft Proxy set 中过滤或删除。
- TUN 模式下，固定 Direct 例外网段应走 Direct 路由，不应被 TUN/Proxy 路径再次捕获。
- redir/tun 连接记录继续显示：
  - redir -> `redir`
  - tun -> `tun`
- redir/tun 命中固定 Direct 例外网段时记录 `direct`。
- 不把 redir/tun 内部路由判断结果显示成 `proxy`。

## SS Server 出口保护

- SS server IP 地址必须始终能从 WAN/物理出口出去；这是全局约束，适用于 socks/http、redir、tun 以及它们同时启用的场景。
- socks/http 代理模式下，`sslocal -> ss-server` 的连接也必须直接从 WAN/物理出口出去，不能被 redir/firewall OUTPUT 规则或 TUN catch-all 再次捕获。
- Linux redir/firewall 模式下：
  - nft/iptables OUTPUT 规则必须对 SS server IP 执行 return，避免 `sslocal -> ss-server` 被重定向回 redir。
  - SS server IP 不应加入 nft Proxy set；如果规则重建或 DNS 学习误加入，必须过滤或删除。
- TUN 模式下：
  - SS server IP 必须安装物理网卡/WAN 路由例外，避免 `sslocal -> ss-server` 进入 TUN。
  - Windows TUN/OpenWrt/Linux TUN 部署脚本都需要保证该例外存在。
- Recent Connections 仍过滤目标为 SS server IP 的连接，因为它是代理隧道出口，不是用户访问目标。

## 系统连接快照

- `recent_connections()` 以 conntrack + `/proc/net/tcp`、`udp`、`tcp6`、`udp6` 为主数据源。
- 读取所有出站连接后过滤：
  - 目标地址为 SS server IP 的连接
  - private / unspecified / listen 行
- 每条系统连接默认标为 `direct`。
- 用 `flow_decisions` 按 5 元组 O(1) 查表：
  - 命中 `socks5_proxy` / `http_proxy` / `redir` / `tun` 时覆盖显示
  - 未命中保持 `direct`

## 补充应用层记录

- 因为 socks/http 的真实出站连接是 `sslocal -> ss-server`，会被 SS server filter 过滤掉，所以还需要从 `record_connection` 补充应用层连接。
- 只补充以下入口类型：
  - `socks5_proxy`
  - `http_proxy`
  - `redir`
  - `tun`
- 不补充 `proxy` / `observed`。
- 和系统快照用 `connection_key` 去重。

## Record 开关和生命周期

- Record 默认不开启；进程启动后不采集 `Recent DNS` / `Recent Connections`，也不维护本轮活动记录。
- 只有管理页面勾选 `Record` 时，才开启 `Recent DNS` 和 `Recent Connections` 功能。
- `Record` 开启时：
  - 清空本轮内存活动状态，包括 `connections`、`dns`、`flow_decisions`、`reverse_domains`、页面去重用的 hash set 等。
  - 清空 `data/record.txt`，作为新一轮记录文件。
  - 开始采集 Recent DNS 和 Recent Connections。
  - Recent Connections 中出现的新连接需要继续追加写入 `data/record.txt`。
- `Record` 关闭时：
  - 停止采集 Recent DNS 和 Recent Connections。
  - 清空本轮内存活动状态和页面去重 hash set。
  - 不要求清空 `data/record.txt`。
- `Record` 每次最多开启 5 分钟。
- 5 分钟到期后，后端自动停止 Record：
  - 页面需要实时感知到状态变化，并自动取消勾选 `Record`。
  - 自动停止时清空本轮内存活动状态和页面去重 hash set。
  - 自动停止时不要清空 `data/record.txt`，保留本轮已经写入的记录。
- 手动再次勾选 `Record` 时，重新清空 `data/record.txt` 并开始新一轮 5 分钟记录。

## 性能设计

### 关键数据结构

- `excluded_remotes`
  - 含义：当前配置中的 Shadowsocks server IP 过滤集合，由 local server 配置在进程启动或配置加载时生成。
  - 用途：过滤 `sslocal -> ss-server` 这类代理隧道出口连接。它不是用户访问的真实目标，如果展示出来会污染 Recent Connections。
  - 数据结构：进程启动或 local server 配置加载时，把 server IP 列表预处理成 `HashSet<IpAddr>`，保存为可复用的过滤集合。`recent_connections()` 每次只接收或读取这个已经构建好的集合，不在轮询请求里重复从 `Vec` 转 `HashSet`。
  - 更新时机：只有配置热更新、server 地址变更或管理后台重新加载配置时才重建一次。普通 Connections tab 轮询不重建。
- `flow_decisions`
  - 含义：应用层记录的权威连接决策表，用来把内核快照中看到的连接重新标记为 socks/http/redir/tun/direct。
  - key：`FlowKey = (source_ip, source_port, destination_ip, destination_port, protocol)`，即 TCP/UDP 5 元组。
  - value：`ConnectionDecision`，也就是应用层入口已经确认过的决策。
  - 作用：conntrack 和 `/proc/net/*` 只能看到系统连接，无法知道这条连接最初来自 SOCKS5、HTTP、redir 还是 TUN；`flow_decisions` 用同一个 5 元组把系统连接映射回应用层决策。
  - 只记录有 IP 的连接。域名目标如果还没有解析成 IP，无法和内核 5 元组匹配，所以不进入 `flow_decisions`。
  - 生命周期：只在本轮 Record 的 5 分钟窗口内存在。Record 开启时清空，Record 关闭或到期时整体清空，因此查询路径不再做逐项过期检查或复杂淘汰。
- `connections`
  - 含义：Recent Connections 的应用层事件队列，保存 `record_connection()` 主动记录的连接事件。
  - 数据结构：`VecDeque<ConnectionEvent>`，只保存本轮 Record 内的事件。
  - 用途：补充系统快照看不到或被 SS server filter 过滤掉的应用层连接，例如 socks/http 的真实用户目标。
- `reverse_domains`
  - 含义：`IpAddr -> domain` 的反向域名缓存，由 DNS 记录填充。
  - 用途：系统快照只有 IP，展示时可用它补回域名，提升 Recent Connections 可读性。
  - 读取方式：`recent_connections()` 开始阶段读取本轮快照，后续读取 conntrack/proc 时只使用快照数据。
- `dedupped_recent_connections`
  - 含义：`recent_connections()` 本次生成返回列表时使用的临时去重集合，不是长期状态，也不跨请求保存。
  - key：`connection_key(event)`，用于描述“一条连接是谁到谁、用什么协议访问哪个端口”。建议包含：
    - `source_ip`
    - `source_port`
    - `destination_ip`
    - `destination_domain`
    - `destination_port`
    - `protocol`
  - 为什么需要：同一条连接可能同时出现在两个来源：
    - 应用层 `connections`：由 socks/http/redir/tun 入口主动记录，decision 更准确。
    - 系统快照：由 conntrack 或 `/proc/net/*` 观察到，覆盖面更完整。
  - 使用方式：
    - 第一步只处理应用层 `connections`：应用层事件先追加到返回结果，并把它们的 `connection_key` 写入 `dedupped_recent_connections`。这一步不因为系统快照而丢弃应用层事件。
    - 第二步才处理系统快照：每条系统快照连接计算同样的 `connection_key`，只有 `dedupped_recent_connections.insert(connection_key)` 成功时才追加到返回结果；如果 insert 失败，说明应用层事件已经占用了这个 key，丢弃的是当前这条系统快照记录。
    - 因此优先级由处理顺序保证：应用层记录先进入结果，系统快照只能补充缺失连接，不能覆盖或过滤已经进入结果的应用层记录。
  - 示例：客户端请求 `119.119.119.119`，规则判定走 redir。redir 入口会主动记录一条 `destination_ip = 119.119.119.119`、`decision = redir` 的应用层连接；conntrack/proc 之后也可能观察到同一个 5 元组。合并时应用层记录已经先进入结果并写入 `dedupped_recent_connections`，系统快照处理在后，遇到同一个 key 时 insert 失败，所以被丢弃的是系统快照记录。页面最终只看到一条 `119.119.119.119` 连接，decision 显示 `redir`。
  - redir 注意事项：不管 nftables 使用 `redirect` 还是 `tproxy`，应用层 `connections` 里的 redir 事件都必须使用用户原始目标构造 `connection_key`。如果错误地使用本地 redir 监听地址，应用层事件和系统快照就不会命中同一个 key，页面会出现重复或错误目标。

### 完整工作流程

1. Record 开启
  - 管理页调用 `POST /api/activity/record/start`。
  - 后端设置 Record 状态为开启，并记录本轮 `record_session_id` 和 5 分钟过期时间。
  - 后端向 Record worker 投递 `StartSession(record_session_id)` 命令。
  - Record worker 串行执行本轮初始化：
    - 清空本轮内存活动状态：`connections`、`dns`、`flow_decisions`、`reverse_domains`、页面去重集合等。
    - 清空 `data/record.txt`，作为新一轮记录文件。
    - 重置 dropped counter。
  - `record_connection()` / `record_dns()` 只有在 Record 状态开启且未过期时，才允许向 Record 队列投递事件。
2. 连接建立时异步投递
  - socks/http/redir/tun 等入口在连接建立或转发时调用 `record_connection(source, target, protocol, decision)`。
  - `record_connection()` 位于转发热路径，只允许做固定小成本操作：
    - 读取 Record 开关、过期时间和当前 `record_session_id`。
    - 如果 Record 未开启或已过期，立即返回。
    - 如果目标是 private / local / link-local 等不应展示的地址，立即返回。
    - 构造轻量 `RecordEvent::Connection { session_id, source, target, protocol, decision }`。
    - 使用非阻塞 `try_send` 投递到 Record 队列。
  - `record_connection()` 不直接写入 `connections`，不直接更新 `flow_decisions`，不直接追加 `record.txt`，也不等待 Record worker 完成。
  - 如果 Record 队列已满，丢弃当前 Record 事件并增加 dropped counter；不能阻塞或反压代理转发。
3. Record worker 消费连接事件
  - Record worker 从队列中串行消费 `RecordEvent::Connection`。
  - 如果事件的 `session_id` 不是当前本轮 Record，说明它来自旧会话或过期投递，直接丢弃。
  - 如果目标是 private / local / link-local 等不应展示的地址，直接跳过。
  - 如果目标包含 `destination_ip` 且协议是 TCP/UDP，就生成 5 元组写入 `flow_decisions`：
    - socks5 入口写 `socks5_proxy`
    - http 入口写 `http_proxy`
    - redir 入口写 `redir`
    - tun 入口写 `tun`
    - 固定 Direct 例外网段写 `direct`
  - 把 `ConnectionEvent` 追加到 `connections`，作为应用层 Recent 事件。
  - 如果该连接是本轮 Record 中首次出现的新连接，追加写入 `data/record.txt`。
4. DNS 记录异步投递和消费
  - DNS 热路径调用 `record_dns()` / `record_dns_error()`。
  - 函数只检查 Record 状态并通过 `try_send` 投递 `RecordEvent::Dns` / `RecordEvent::DnsError`，不直接更新 Recent DNS，也不写文件。
  - Record worker 消费 DNS 事件后：
    - 写入 Recent DNS。
    - 用 DNS 结果维护 `reverse_domains`，建立 `IP -> domain` 映射。
    - 丢弃旧 `session_id` 或过期事件。
  - 后续系统快照只看到 IP 时，可以通过 `reverse_domains` 补上域名。
5. 管理页请求 Recent Connections
  - 页面轮询 Record 状态。
  - 如果 Record 关闭或 5 分钟到期，页面清空 Recent DNS / Recent Connections 表格，不再请求列表数据；后端也应清理本轮内存活动状态。
  - 如果 Record 开启，页面调用 `GET /api/activity/connections`，后端执行 `recent_connections()`，并使用已经预构建好的 SS server IP 过滤集合。
  - `recent_connections()` 读取的是 Record worker 已经维护好的本轮快照；页面请求不参与热路径记录。
6. `recent_connections()` 合并数据
  - 使用进程启动或配置加载时已经构建好的 `excluded_remotes: HashSet<IpAddr>`，用于过滤 SS server IP。
  - 读取本轮 Record 的内存快照：
    - `connections`
    - `flow_decisions`
    - `reverse_domains`
  - 这里不需要 routing write lock，也不需要在查询路径做逐项清理：
    - Record 只有 5 分钟窗口，数据生命周期由 Record start/stop/expire 统一控制。
    - Record 开启时整体清空旧状态，关闭或过期时整体清空本轮状态。
    - `recent_connections()` 只负责读快照和合并展示，不负责维护生命周期。
  - 从 `connections` 倒序取出应用层事件，并过滤 SS server IP。
  - 用这些应用层事件初始化 `dedupped_recent_connections` 去重集合。
  - 读取系统连接快照：
    - conntrack
    - `/proc/net/tcp`
    - `/proc/net/udp`
    - `/proc/net/tcp6`
    - `/proc/net/udp6`
  - 每条系统连接先过滤 listen、unspecified、private、SS server IP。
  - 系统连接默认标记为 `direct`。
  - 如果系统连接 5 元组命中 `flow_decisions`，用权威决策覆盖默认值。
  - 如果 `dedupped_recent_connections` 中没有同一条连接，则追加到返回结果。
  - 最后按 timestamp 倒序排序后返回。
7. Record 关闭或过期
  - 手动关闭时，管理页调用 `POST /api/activity/record/stop`。
  - 5 分钟到期时，后端自动把 Record 状态切到关闭。
  - 后端向 Record worker 投递 `StopSession(record_session_id)` 命令。
  - Record worker 清空本轮内存活动状态和页面去重集合，停止接受旧 `session_id` 事件。
  - 不清空 `data/record.txt`，保留本轮已经写入的记录。
  - 关闭后热路径再次调用 `record_connection()` / `record_dns()` 会因为 Record 状态关闭而立即返回。

### 为什么性能好

- Record 异步化，避免阻塞实时转发：
  - 转发热路径只做最小工作：
    - 读取 Record 开关和过期状态。
    - Record 未开启时立即返回。
    - Record 开启时构造轻量 `ConnectionEvent` / `DnsEvent`。
    - 使用非阻塞 `try_send` 投递到后台 Record 队列。
  - 热路径禁止做以下操作：
    - 等待 async lock。
    - 写 `record.txt`。
    - 读取 conntrack 或 `/proc/net/*`。
    - 做页面级去重。
    - 做逐项清理、排序或复杂聚合。
  - 后台 Record worker 负责消费队列并维护本轮状态：
    - `connections`
    - `dns`
    - `flow_decisions`
    - `reverse_domains`
    - `record.txt` 追加写入
  - 队列必须有容量上限。高并发时如果队列满，优先丢弃 Record 事件并增加 dropped counter，不能反压代理转发。
  - 因此 Record 对实时路由转发的影响被限制为固定成本：一次开关判断、一次事件构造和一次非阻塞入队；不会因为磁盘 IO、页面轮询或系统快照采集拖慢连接处理。
  - 严格说不能做到“完全没有影响”，因为开启 Record 时总要采集元数据；但可以做到不阻塞、不等待、不反压，性能影响可控且可观测。
- SS server 过滤从线性扫描变成哈希查找：
  - `excluded_remotes` 通常很小，但系统快照连接数可能很大。
  - 每条连接都要判断是否是 SS server 出口，把列表在启动或配置加载时预处理成 `HashSet<IpAddr>` 后，过滤成本稳定为 O(1)。
  - 这个 HashSet 不在每次 Connections tab 轮询时重建，避免把固定配置成本放到查询热路径。
- 决策重标记是 5 元组 O(1) 查表：
  - 不按 IP、端口或域名单独模糊搜索，避免误判和额外扫描。
  - `flow_decisions` 的 key 与 conntrack/proc 能提供的连接身份一致，系统快照行可以直接构造同一个 key 查询。
- 应用层事件和系统快照只做一次合并：
  - 先把 `connections` 放入结果并建立 `dedupped_recent_connections`。
  - 再扫描系统快照，只有未见过的连接才追加。
  - 去重是 HashSet O(1)，不会出现双层循环比较。
- 查询路径不做生命周期维护：
  - `recent_connections()` 不拿 routing write lock 做逐项清理。
  - 定期清理和容量淘汰都不是必要设计，因为 Record 每次最多 5 分钟。
  - 生命周期集中在 Record start/stop/expire：开启时清空，关闭或过期时整体释放。
  - conntrack 和 `/proc/net/*` 读取可能涉及文件 IO 和解析，查询路径只做快照合并，避免阻塞 DNS、连接记录和规则更新。
- 内存增长有边界：
  - Record 默认关闭，未开启时不采集活动数据。
  - Record 每次最多 5 分钟，关闭或过期时清空本轮活动状态，避免后台长期积累。
  - 如需防御极端高 churn 环境，可保留简单最大数量上限，但不需要把逐项清理放到查询路径。
- 热路径尽早返回：
  - `record_connection()` / `record_dns()` 在 Record 未开启或过期时立即返回，正常代理流量不承担 Recent 活动记录成本。
  - private/local 目标在记录入口直接跳过，减少无意义事件和后续合并成本。
- 系统快照采集保守串行：
  - 先串行读取 conntrack/proc，逻辑简单且避免额外任务调度。
  - 如果实测路由器或高连接数环境下慢，再把系统快照采集放到 `spawn_blocking` 或拆成并行读取；这属于后续性能验证后的优化，不影响当前方案正确性。

## 代码改动点

- `crates/shadowsocks-service/src/local/routing.rs`
  - 调整 `ConnectionDecision`，去掉或停止使用 `Proxy` / `Observed` 展示值。
  - 修改 `recent_connections()` 合并逻辑。
  - 修改 `collect_system_connections()` 默认 decision 为 `Direct`。
  - 增加 Record 状态、5 分钟过期时间和活动状态清理接口。
  - `record_connection`、`record_dns`、`record_dns_error` 在 Record 未开启或已过期时不写入 Recent 数据。
- `crates/shadowsocks-service/src/local/http/utils.rs` / `http_service.rs`
  - HTTP 入口默认走 SS server。
  - HTTP 目标命中固定 Direct 例外网段时走 Direct，并记录 `ConnectionDecision::Direct`。
  - 记录 `ConnectionDecision::HttpProxy`。
- `crates/shadowsocks-service/src/local/socks/server/socks4/tcprelay.rs`
- `crates/shadowsocks-service/src/local/socks/server/socks5/tcprelay.rs`
  - SOCKS 入口默认走 SS server。
  - SOCKS 目标命中固定 Direct 例外网段时走 Direct，并记录 `ConnectionDecision::Direct`。
  - 记录 `ConnectionDecision::Socks5Proxy`。
- `crates/shadowsocks-service/src/local/net/udp/association.rs`
  - 避免记录 `ConnectionDecision::Proxy`。
  - 如需记录 UDP，应由调用入口传入 socks/redir/tun 类型；否则系统快照默认 direct。
  - UDP 目标命中固定 Direct 例外网段时记录 `ConnectionDecision::Direct`。
- redir/tun 相关入口
  - 目标命中固定 Direct 例外网段时走 Direct，并记录 `ConnectionDecision::Direct`。
  - Linux nft/TUN 同步逻辑需要确保固定 Direct 例外网段不会进入 Proxy 捕获路径。
- `crates/shadowsocks-service/src/local/web_admin/mod.rs`
  - `POST /api/activity/record/start`：清空 `record.txt`，清空本轮内存活动状态，开启 5 分钟 Record。
  - `POST /api/activity/record/stop`：停止 Record，清空本轮内存活动状态，不清空 `record.txt`。
  - `GET /api/activity/record/status`：返回 `recording`、`expires_at`、`remaining_seconds`，并在过期时触发自动停止和内存清理。
  - Connections tab 每秒轮询 status；过期后自动取消勾选 `Record` 并清空页面表格。
- `routing.md`
  - 更新 Recent Connections 和连接路径说明。

## 验证

- `cargo check --features 'full local-web-admin local-http-rustls' --bin sslocal`
- `cargo check --no-default-features --features 'local local-http-rustls' --bin sslocal`
- `cargo test -p shadowsocks-service --features local-web-admin,local-dns,local-redir,local-tun local::routing`
- 扫描确保管理页 Recent Connections 不会再输出 `proxy` / `observed`。

