# eGatefilter — 项目说明

Go 语言实现的网络代理网关，支持 HTTP/HTTPS 内容过滤与 SOCKS5 代理。
现已扩展为抓包软件：支持 TCP / HTTP / HTTPS 抓包，元数据写入 SQLite，具体包文保存为本地文件，并提供 Vue Vite 前端 GUI 与 WebSocket 实时推送。

修改项目功能与结构时需要同步更新此文件，确保后续开发者与 AI 工具理解各目录职责、配置格式和新增接口。

---

## 关于指令提示文件

1, 工作区中的/CLAUDE.md , /AGENTS.md 这三个文件是使用硬连接指向的同一个文件,所以修改指令提示文件时不要重新创建,只能修改

2, 代码有较大范围的修改时,需要同时更新指令提示文件

---

## 项目结构

```text
eGatefilter/
├── main.go          — 入口：解析配置、加载 CA、启动监听器；定义 Proxy 结构体
├── config.go        — Config / RuleConfig / ContentRule 结构体 + JSON 加载
├── rules.go         — RuleEngine：通配符域名匹配，返回第一条命中的 Rule
├── mitm.go          — CertManager：加载 CA、按需签发叶证书（内存缓存）
├── mixed_listener.go — 混合协议监听器：基于首字节嗅探分流 SOCKS5 与 HTTP 连接
├── http_proxy.go    — HTTP 代理服务器（CONNECT 隧道 + 普通 HTTP + 缓存写入）
├── socks5.go        — SOCKS5 匿名代理服务器（RFC 1928，无认证）
├── filter.go         — 响应体内容过滤（字符串/正则，透明处理 gzip）
├── file_replace.go  — filter 文件级替换（URL 路径通配符 → 本地文件/目录映射）
├── cache.go         — 响应体本地缓存（按 URL 目录结构写入 cache/ 文件夹）
├── capture.go       — 抓包核心：SQLite 元数据、包文文件保存、HTTP/TCP 记录封装
├── gui.go           — 内置 GUI/API/WebSocket 服务：查询抓包记录、读取包文、实时推送
├── process_windows.go — Windows 平台支持：基于端口反查本机请求的进程 PID、名称和路径
├── process_other.go   — 其他平台支持（空实现）
├── upstream.go      — 出口代理：直连 / SOCKS5 / HTTP CONNECT 拨号封装
├── pac.go           — PAC 文件/URL 加载与 FindProxyForURL JS 求值（otto 引擎）
├── config.json      — 运行时配置（规则在此维护）
├── rootCA/
    ├── rootCA.crt   — eATM Root CA 证书（RSA，有效期至 2034-10-20）
    ├── rootCA.key   — CA 私钥（PKCS1 RSA）
├── capture/
│   ├── capture.sqlite — SQLite 抓包元数据数据库
│   └── bodies/        — 请求/响应/TCP 双向流包文文件，按域名/IP分目录保存
└── web/
  ├── package.json — Vue Vite 前端依赖与脚本
  ├── src/         — 前端源码
  └── dist/        — 前端构建产物，GUI 服务默认从此目录加载
```

---

## 编译与运行

```bash
go mod tidy
go build -o gatefilter.exe .
./gatefilter.exe -c config.json
cd web && npm install && npm run build
```

默认端口：混合监听端口 `:8081`（自动识别 HTTP 代理、SOCKS5 代理及浏览器直接访问 GUI，可在 config.json 修改）。
GUI 访问地址：浏览器访问 `http://127.0.0.1:8081`。

---

## 配置文件格式（config.json）

```jsonc
{
  // 支持 // 行注释 和 /* 块注释 */
  "listen": {
    "mixed": ":8081",
    "http": "",
    "socks5": ""
  },
  "ca": {
    "cert": "rootCA/rootCA.crt",
    "key":  "rootCA/rootCA.key",
    "crl_url": "http://127.0.0.1:8081/egatefilter.crl"
  },
  "cache_dir": "cache",
  "capture": {
    "enabled": true,
    "db_path": "capture/capture.sqlite",
    "body_dir": "capture/bodies"
  },
  "gui": {
    "enabled": true,
    "listen": "",
    "dist_dir": "web/dist"
  },
  "rules": [
    {
      "name": "规则名称",
      "domains": ["*.example.com", "exact.com", "*"],
      "action": "filter",
      "paths": ["/index.html", "/test*.html"],
      "target": { "host": "192.168.1.1", "port": 8080 },
      "file": [
        { "match": "/logo.png", "local": "filter/assets/new-logo.png" },
        { "match": "/i18n/*", "local": "" }
      ],
      "content": [
        { "match": "广告文字", "replace": "", "paths": ["/index.html"] },
        { "match": "<div[^>]+ad[^>]*>.*?</div>", "replace": "", "regex": true }
      ]
    }
  ]
}
```

### 字段说明

| 字段 | 说明 |
| --- | --- |
| `listen.mixed` | 混合监听地址，自动区分并处理 SOCKS5, HTTP/HTTPS 代理以及 GUI Web 服务 |
| `listen.http` | HTTP 代理监听地址（可选，混合模式下可留空） |
| `listen.socks5` | SOCKS5 监听地址（可选，混合模式下可留空） |
| `ca.crl_url` | MITM 叶证书写入的 CRL 分发点，供 Windows Schannel 等客户端做吊销检查；为空时按监听端口自动生成 `/egatefilter.crl` |
| `cache_dir` | 响应缓存根目录，默认 `"cache"`，留空禁用缓存 |
| `capture.enabled` | 是否启用抓包记录 |
| `capture.db_path` | SQLite 抓包元数据数据库路径 |
| `capture.body_dir` | 包文文件保存目录，内部按域名/IP分文件夹，文件名前缀为年月日时分秒毫秒 |
| `gui.enabled` | 是否启用内置 GUI/API/WebSocket 服务 |
| `gui.listen` | 独立 GUI 服务监听地址（可选，混合模式下可留空） |
| `gui.dist_dir` | Vue Vite 构建产物目录，默认 `web/dist` |
| `rules[].domains` | 域名列表，支持 `*.example.com`、精确匹配、`*`（全匹配） |
| `rules[].action` | `block` \| `redirect` \| `filter` \| `passthrough` |
| `rules[].target` | `redirect` 专用，指定转发目标 host + port |
| `rules[].paths` | `filter` 专用，URL 路径通配符列表（如 `/index.html`、`/test*.html`）；为空表示全路径 |
| `rules[].content` | `filter` 专用，内容替换规则列表 |
| `rules[].file` | `filter` 专用，整文件替换规则列表（优先于 `content`） |
| `content[].regex` | `true` 时 match 按 Go regexp 解析，否则按字面字符串 |
| `content[].paths` | `content` 级路径通配符；为空表示该条 content 对当前 rule 下所有路径生效 |
| `file[].match` | URL 路径通配符（如 `/logo.png`、`/i18n/*`） |
| `file[].local` | 本地替换路径；为空时自动映射到 `filter/{domain}/{request_path}` |

### action 说明

| action | HTTP 代理 | SOCKS5 代理 |
| --- | --- | --- |
| `block` | 返回 HTTP 403 | 返回 SOCKS5 reply 0x02 |
| `redirect` | 转发到 target host:port（透明隧道） | 同左 |
| `filter` | `rules[].paths` 先筛选路径，再按 `content[].paths` 做细粒度文本过滤；`file` 可做整文件替换；命中后缓存到本地 | TLS 端口做 MITM，其他端口明文过滤；逻辑同左 |
| `passthrough` | 纯透明转发（默认行为） | 同左 |

未命中任何规则时行为等同 `passthrough`。

---

## 核心模块详解

### upstream.go — 出口代理拨号器

```go
// NewUpstreamDialer 从配置创建拨号器；cfg 为 nil 或 type="none" 时返回 nil（直连）
func NewUpstreamDialer(cfg *UpstreamConfig) (*UpstreamDialer, error)

// Dial 连接 addr（host:port），nil receiver 等同直连
func (d *UpstreamDialer) Dial(addr string) (net.Conn, error)

// DialTLS 在 Dial 基础上完成 TLS 握手
func (d *UpstreamDialer) DialTLS(addr, serverName string) (*tls.Conn, error)

// DialContext 兼容 http.Transport.DialContext
func (d *UpstreamDialer) DialContext(_ context.Context, _, addr string) (net.Conn, error)
```

路由逻辑：

- `type=socks5` → 所有出口走 `socks5_addr`
- `type=pac`    → 每次请求调用 `PACEvaluator.FindProxy`，解析 `DIRECT / SOCKS5 host:port / PROXY host:port`
- `type=none`   → 直接 `net.DialTimeout`

### capture.go — 抓包记录

```go
// NewCaptureManager 初始化 SQLite 数据库和包文目录
func NewCaptureManager(cfg CaptureConfig) (*CaptureManager, error)

// Insert 写入抓包元数据，写入成功后通过 CaptureHub 实时广播
func (m *CaptureManager) Insert(record *CaptureRecord) int64

// List / Get / ReadBody 供 GUI API 查询记录与读取包文预览
func (m *CaptureManager) List(limit, offset int, keyword string) ([]CaptureRecord, error)
func (m *CaptureManager) Get(id int64) (*CaptureRecord, error)
func (m *CaptureManager) ReadBody(id int64, part string) (*CaptureBody, error)

// Clear 清空 SQLite 抓包元数据，并删除 body_dir 下全部本地包文文件
func (m *CaptureManager) Clear() error
```

抓包策略：

- HTTP：记录请求头、请求体、响应头、响应体。
- HTTPS：复用现有 MITM 能力解密后记录 HTTP 明文包文。
- SOCKS5 + HTTPS MITM：客户端目标常是 IP，抓包记录的域名优先使用 TLS SNI；请求头保存时会显式补写 `Host` 行，因为 Go 的 `http.Request.Host` 不在 `Header` map 中。
- TCP：原始隧道按上行/下行双向流保存 `.bin` 包文文件，同时记录流量大小、目标、耗时等元数据。
- 包文目录：`capture/bodies/{domain或ip}/{yyyyMMddHHmmss.SSS}_{part}.{ext}`；HTTP/HTTPS 响应按 URL 或 Content-Type 推断扩展名，请求/响应头为 `.txt`，TCP 为 `.bin`。
- SQLite 仅保存索引、路径和摘要字段，具体包文不写入数据库。

### gui.go — GUI / API / WebSocket

```text
GET /api/captures?limit=100&offset=0&q=keyword
DELETE /api/captures
GET /api/captures/{id}
GET /api/captures/{id}/body/{requestHeader|requestBody|responseHeader|responseBody}
WS  /ws/captures
```

WebSocket 消息格式：

```json
{ "type": "capture", "data": { "id": 1, "protocol": "https", "host": "example.com" } }
{ "type": "clear" }
```

前端“清空记录”按钮调用 `DELETE /api/captures`，会同步清空 SQLite 元数据与 `capture.body_dir` 下的包文文件；清空成功后通过 WebSocket 广播 `clear` 消息让所有已打开 GUI 页面刷新为空列表。

### web/ — Vue Vite 前端

- `web/src/main.ts`：抓包列表、详情、包文预览、WebSocket 实时更新。
- `web/src/style.css`：现代化深色 GUI 样式。
- `web/.env.example`：前端后端地址默认值配置示例，可复制为 `web/.env` 后设置 `VITE_API_BASE`。
- 开发：`cd web && npm run dev`
- 构建：`cd web && npm run build`，后端默认服务 `web/dist`。
- 前端 WebSocket 状态右侧提供“配置”按钮，默认隐藏后端地址配置栏；后端 HTTP 与 WS 使用同一组 IP:端口，输入 `127.0.0.1:8081` 或 `http://127.0.0.1:8081` 后点击“保存并重连”写入浏览器 `localStorage`（键名：`captureServerBase`），刷新页面后继续生效。
- 前端后端地址默认值：优先读取 `localStorage.captureServerBase`；没有保存值时读取 `VITE_API_BASE`；仍为空时 API 使用当前页面同源地址，WebSocket 由同一地址自动推导。
- 前端抓包搜索框为本地实时过滤：输入时立即按协议、方法、域名、URL、路径、状态码、规则、动作、客户端/目标地址、进程名/路径和备注过滤当前已加载列表；“刷新”按钮仅重新拉取最新记录，不再携带搜索关键字。
- 前端过滤关键字在前端本地持久化（键名：`captureKeyword`），刷新页面后自动还原。
- 请求/响应头、体包文查看采用 Monaco Editor 渲染，支持根据内容自动切换高亮语法，支持中英双语与双仓库地址动态加载；已关闭自动换行和字符拼写/Unicode安全检查；若内容是 JSON 则自动进行格式化排版。- 抓包记录基本元数据卡片移入右侧面板首位的“信息” Tab，以中文 Key-Value 纯文本格式统一使用 Monaco Editor 编辑器显示，提供了便捷的数据查看与文本复制能力。- 大模型协议（Gemini 与 OpenAI）智能解析展示：当请求体或响应体（如 LLM SSE 流协议）符合大模型协议时，提供“交互视图”与“原始代码”双视图切换。交互视图自动还原拼接文本、系统提��词、对话气泡气泡流、大模型调用工具函数（Function Calls）、可用工具列表（Tools Declared）以及 Token 统计指标；支持大模型单体工具执行协议（`functionCall`、`functionResponse`）的独立捕获与交互式高亮排版展示；支持在对话历史（contents/messages）气泡中自动解析并渲染内嵌的工具调用与返回结果卡片；对话文本部分支持完整的 Markdown 富文本渲染展示。
- 交互视图组件化：支持在 `web/src/components/` 编写独立的协议交互渲染组件（如 `GeminiView.vue`、`OpenaiView.vue`），并在 `App.vue` 中由 `detectedFormat` 统一检测与路由分发，利于未来扩展其他类型的流式协议。

### pac.go — PAC 求值器

```go
// NewPACEvaluator 从本地文件或远程 URL 加载 PAC 脚本，注入标准帮助函数
func NewPACEvaluator(filePath, pacURL string) (*PACEvaluator, error)

// FindProxy 调用 FindProxyForURL(url, host)，返回第一条可用 proxyEntry
// 线程安全（内部 sync.Mutex）
func (p *PACEvaluator) FindProxy(urlStr, host string) (proxyEntry, error)
```

实现的 PAC 帮助函数：
`isPlainHostName` `dnsDomainIs` `localHostOrDomainIs` `isResolvable`
`isInNet` `dnsResolve` `myIpAddress` `dnsDomainLevels` `shExpMatch`
`convert_addr` `weekdayRange`(stub) `dateRange`(stub) `timeRange`(stub) `alert`(stub)

### config.go — 配置加载

```go
// 读取文件 → stripComments() 剥注释 → encoding/json 解析，无外部依赖
func LoadConfig(path string) (*Config, error)

// 状态机实现：跳过 // 行注释和 /* */ 块注释，字符串内容原样保留
func stripComments(src []byte) []byte

type Config struct {
    Listen   struct{ Mixed, HTTP, SOCKS5 string }
    CA       struct{ Cert, Key string }
    CacheDir string        // 响应缓存目录，默认 "cache"，空字符串禁用
    Rules    []RuleConfig
}
```

### rules.go — 规则引擎

```go
// 匹配入口：host 可带端口（如 "example.com:443"）
func (e *RuleEngine) Match(host string) *Rule

// 通配符规则：
//   "*.example.com" → 匹配任意子域（sub.example.com、a.b.example.com）
//   "example.com"   → 精确匹配
//   "*"             → 匹配所有域名
func matchWildcard(pattern, domain string) bool
```

### mitm.go — 证书管理

```go
// 加载 CA，支持 PKCS1 RSA / EC / PKCS8 格式私钥
func LoadCA(certFile, keyFile string) (*CertManager, error)

// 加载 CA 并设置写入叶证书的 CRL 分发点
func LoadCAWithCRLURL(certFile, keyFile, crlURL string) (*CertManager, error)

// 返回域名/IP 对应的叶证书（首次生成 RSA 2048，之后从内存缓存取；IP 会写入 IP SAN，域名会写入 DNS SAN）
func (cm *CertManager) GetCert(host string) (*tls.Certificate, error)

// 构造用于 tls.Server() 的配置（含 NextProtos: http/1.1，禁用 HTTP/2；优先按客户端 TLS SNI 动态签发证书）
func (cm *CertManager) TLSServerConfig(host string) (*tls.Config, error)

// 生成 CA 签名的空 CRL，供 /egatefilter.crl 返回，解决 Schannel 吊销检查失败
func (cm *CertManager) EmptyCRL() ([]byte, error)
```

### http_proxy.go — HTTP 代理

```go
func (p *Proxy) StartHTTP(addr string) error

// CONNECT 处理：block→403 | filter→doMITM | redirect→rawTunnel | 其他→rawTunnel
// 普通 HTTP：block→403 | filter→转发+applyFileReplacement/FilterResponse(按 paths 双层匹配)+cacheResponse | redirect→换host | 其他→转发

// MITM：生成证书 → TLS握手客户端 → 连接真实服务器 → bridgeHTTP()
func (p *Proxy) doMITM(conn net.Conn, host string, rule *Rule)

// HTTP/1.x 双向桥接：读请求→转发→读响应→applyFileReplacement/FilterResponse(按 paths 双层匹配)→cacheResponse→写回客户端
// 循环处理 keep-alive，直到任一端关闭
func (p *Proxy) bridgeHTTP(client, server net.Conn, host string, rule *Rule)

// 纯字节隧道（不解析内容）
func rawTunnel(conn net.Conn, target string)
```

**注意**：filter 规则会自动删除请求头 `Accept-Encoding`，
确保服务器返回明文响应，方便过滤和缓存（无需处理压缩格式）。

### socks5.go — SOCKS5 代理

```go
func (p *Proxy) StartSOCKS5(addr string) error

// 每个连接流程：
//   1. 读 greeting → 协商 NO AUTH（0x00）
//   2. 读 CONNECT → 解析 IPv4/IPv6/域名 + 端口
//   3. 匹配规则 → block/redirect/filter/tunnel
//
// filter 规则：
//   isTLSPort(port) == true  → p.doMITM()
//   isTLSPort(port) == false → 直连 + p.bridgeHTTP() 明文过滤

// TLS 端口（443, 8443, 993, 995, 465, 636, 5061）
func isTLSPort(port int) bool
```

### filter.go — 内容过滤

```go
// 就地替换 resp.Body，自动处理 Content-Encoding: gzip
// 只处理文本类型（text/*、json、javascript、xml）
func FilterResponse(resp *http.Response, rules []ContentRule, urlPath string)

func applyRules(body []byte, rules []ContentRule, urlPath string) []byte
```

### file_replace.go — 文件级替换

```go
// 对 rule.File 逐条匹配 URL 路径，命中后用本地文件替换整份响应体
func (p *Proxy) applyFileReplacement(resp *http.Response, host, urlPath string, rule *Rule) bool
```

### cache.go — 响应缓存

```go
// 读取 resp.Body，后台写盘，再用新 bytes.Reader 替换 resp.Body（不阻塞代理）
// 仅在 rule.Action == ActionFilter 时被调用
func (p *Proxy) cacheResponse(method, host, urlPath, rawQuery string, resp *http.Response)

// 构建缓存文件路径：{cacheDir}/{host}/{urlPath}[@{queryMD5[:4]}][.ext]
// 示例：cache/example.com/article/news@1a2b3c4d.html
func buildCachePath(cacheDir, host, urlPath, rawQuery string) string
```

缓存目录结构示例：

```text
cache/
└── www.example-news.com/
    ├── index                     ← GET /
    ├── article/
    │   ├── 123                   ← GET /article/123
    │   └── 456@a1b2c3d4          ← GET /article/456?page=2
    └── static/
        └── app@5e6f7a8b.js       ← GET /static/app.js?v=3
```

---

## HTTPS MITM 说明

客户端需要将 `rootCA/rootCA.crt` 安装为**受信任的根证书颁发机构**，
否则浏览器/客户端会报 `ERR_CERT_AUTHORITY_INVALID`。

- Windows：双击 rootCA.crt → "安装证书" → "本地计算机" → "受信任的根证书颁发机构"
- Linux/macOS：`sudo trust anchor --store rootCA.crt`（系统不同命令不同）
- Firefox：设置 → 隐私与安全 → 证书 → 导入

---

## 依赖

| 包 | 用途 |
| --- | --- |
| 标准库 `encoding/json` | 解析 config.json |
| 标准库 `crypto/tls` | TLS 握手 / 证书生成 |
| 标准库 `net/http` | HTTP 代理服务器 / 客户端 |
| 标准库 `compress/gzip` | 响应体 gzip 解压/重压 |
| 标准库 `crypto/md5` | 查询字符串哈希（缓存文件命名） |

无外部依赖。

---

## 待扩展功能（未实现）

- 透明代理（需 iptables/WFP 流量重定向）
- HTTP/2 MITM 支持（当前强制 HTTP/1.1）
- 持久化证书缓存（重启后复用，避免重新签发）
- 从缓存直接响应（当前只写不读）
- 访问日志（记录域名/URL/规则命中情况到文件）
- 规则热重载（SIGHUP 触发配置重读）
