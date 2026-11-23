---
name: mini-program
description: 微信小程序渗透：wxapkg 解密解包、接口/密钥/云环境提取、登录态与越权、云开发、支付与开放能力、证据与报告
license: MIT
when_to_use: 用户上传 .wxapkg/.zip 或提到微信小程序/AppID/小程序码，要求做安全测试、代码审计、接口挖掘或越权验证
tags:
  cwe: [CWE-306, CWE-639, CWE-798, CWE-862]
  attack: [T1190, T1552]
  class: [mobile, api, cloud]
---

# 微信小程序渗透

小程序漏洞的主体是 **API 鉴权缺失、水平/垂直越权、业务逻辑、前端信任、云开发配置错误、硬编码密钥**，不是传统 Web 注入。核心思路：**包是入口，后端才是主战场**。

## 0. 输入判定

- 附件通常在 `tasks/<id>/uploads/`（任务页）或 `sessions/<id>/uploads/`（对话页），任务描述/消息里带绝对路径。
- 支持单个 `.wxapkg`、多个包（主包+分包）、含包的 `.zip`、或已解压目录。
- AppID 提取：路径段/目录名/文件名里的 `wx[0-9a-f]{16}`；也可让用户直接给出。
  **不要把微信账号 `wxid_...` 当 AppID**——V1MMWX 解密填错只会出乱码，不会报密码错误。
- 小程序包可能来自：PC 微信 3.x/4.x 缓存、Android/iOS 缓存、用户导出。PC 包通常带 `V1MMWX` 外壳；手机端通常明文。

## 1. 解包（先跑这一条）

```bash
bash "${SKILL_DIR}/scripts/miniapp_unpack.sh" \
  --in "<wxapkg 或 zip 或目录的绝对路径>" \
  --out "<taskRoot>/miniapp" \
  --appid "<wx...>"          # 可省略，脚本会从路径推断
```

产物（`<taskRoot>/miniapp/<appid>/`）：

| 路径 | 内容 |
|---|---|
| `raw/` | 自研安全解析器提取的原始文件（防路径穿越；即使反编译失败也可审计 JS/JSON） |
| `decrypted/` | V1MMWX 解密后的包 |
| `src_wedecode/` | wedecode 质量解包（若安装；WXML 绑定保留最好，4.x 支持好） |
| `src_unveilr/` | unveilr 质量解包（若设置 `UNVEILR_DIR`；WXML 交叉验证） |
| `src_killwxapkg/` | KillWxapkg 兜底（沙箱/专用目录；WXML 可能丢绑定） |
| `source` | 质量分最高的产物（符号链接，优先用它做审计） |
| `manifest.json` | AppID、包哈希、工具、质量分、警告 |

脚本会：检测明文/`V1MMWX`/mac 旧加密 → AppID 已知则解密 → 索引预校验（拒绝 `../`、绝对路径、UNC、NUL、超长名）→ 安全提取 → 依次尝试 wedecode/unveilr/killwxapkg → 每个产物过质量门禁 → 选最优。

**不要只看工具退出码**：KillWxapkg 失败也可能 exit 0；以 `manifest.json` 的 `quality.status` 与 `source` 是否存在为准。质量 `partial` 时优先动态验证补齐。

## 2. 静态审计

```text
miniapp_audit(dir="<taskRoot>/miniapp/<appid>/source")
```

输出（`runDir/miniapp-audit/`）：

- `report.json`：routes / endpoints / secrets / cloud / sign_candidates / sourcemaps / osv / summary
- `endpoints.txt`：每行 `METHOD URL  # file:line`
- `secrets.txt`：脱敏值 + 类型 + `file:line` + 上下文

审计重点：
1. **接口与域名**：`wx.request/uploadFile/downloadFile/connectSocket`、`wx.cloud.callFunction`、`collection`、`uploadFile/downloadFile`、`web-view src`、第三方 SDK。
2. **密钥**：AppSecret（32 hex）、支付密钥、云 AK/SK、地图 key、JWT、AES key/iv、私钥、上传 token。
3. **云开发**：`env`、云函数名、集合名、存储路径。
4. **签名/加密**：`sign/hmac/md5/sha/aes/encrypt/decrypt` 的定义与调用点。
5. **路由**：`app.json`/`app-config.json` 的 pages/subPackages/plugins；高价值页面（登录/支付/订单/地址/会员/上传）。
6. **sourcemap**：`*.js.map`、`//# sourceMappingURL`；命中即高价值。
7. **依赖**：`package.json` → OSV。

输出纪律：每条接口/密钥必须带 `file:line`；密钥只留脱敏值；没有证据的猜测写 `hypothesis`，不要当 confirmed。

## 3. 与本平台的衔接

| 小程序发现 | 平台动作 |
|---|---|
| AppID / 小程序本体 | `insert_assets(type=app, bundle_id=<AppID>, app_name=<名称>)` |
| 接口清单 | `insert_assets(type=endpoint)`（带来源与状态码） |
| 硬编码密钥 | `record_fact`（全文，供后续验证）+ `save_evidence`（脱敏文件/行号） |
| 云环境/函数/集合 | `record_fact`；按 `references/04-cloudbase-security.md` 做只读探测 |
| 抓到的请求/响应 | `traffic_search` / `traffic_get` + finding 绑定流量 |
| 越权候选 | `session_login` 建 A/B 两个身份 → `http_request` 对照 → `diff_responses` |
| 漏洞 | `report_finding`（源码行 + 请求响应 + 复现命令 + 影响 + 修复） |
| 解包产物 | `save_evidence`（源码行、manifest、审计 JSON） |

平台既有小程序条目（不要重复造轮子）：
- `skills/src-hunting/references/authbypass-test.md:108,309`（小程序码/跳转码、`loginByOpenId` 空值）
- `skills/src-hunting/references/idor-test.md:187,496`（云 Registry、打包 JS 写死 token）
- `skills/src-hunting/references/打穿短表.md:20,30-31,53,92`（云函数 Registry、客服链、空 openId）

## 4. 动态验证

### 4.1 抓包（PC 微信 / 模拟器 / iOS）

PC 微信 3.4.5+ 的小程序由 `WeChatAppEx.exe`/WMPF 运行时承载，**不读系统代理**。用 Proxifier 按进程强制转发：

- 进程规则：`WeChat.exe;WeChatAppEx.exe;WeChatPlayer.exe;WechatBrowser.exe;WeChatAppEx*.exe`
- 代理指向平台 MITM 地址；安装并信任平台 CA；勾选 `Use target hostname in proxy request if available`
- 安卓 7+ 不信任用户证书：用 Android 5/6 模拟器，或 root + Magisk 系统证书，或 Postern SOCKS
- iOS：Wi-Fi 代理 + 描述文件 + 证书信任设置
- 抓不到包：按 `references/02-traffic-interception.md` 的原因树排查（WMPF 网络栈/证书/pinning/QUIC/代理冲突）

### 4.2 登录态与越权

- `session_login` 支持表单/JSON/Header/Cookie；小程序 token 常在 `Authorization`、`X-Token`、`token` 或 query。
- 建两个测试账号的 session（A/B），对每个敏感接口跑 10 态矩阵（见 `references/03-auth-and-session.md`）。
- 对象 ID 用 A/B 双账号对照，取最小样本。
- `diff_responses` 对比 A/B 响应结构差异（长度/字段/状态码）。

### 4.3 云开发/支付/开放能力

- 云函数：函数名全集、参数最小化/置空/换 ID、`getWXContext().OPENID` vs 入参 openid。
- 数据库/存储：规则 `read:true`/`write:true`、`doc.get`、`aggregate/watch`、fileID 枚举。
- 支付：服务端算价、回调验签、退款累计、幂等（只做测试商户/沙箱）。
- 开放能力：小程序码 `scene/page`、URL Link `query`、订阅消息 `touser/page`、跨小程序跳转 `appId/path/extraData`。

## 5. 参考文件（按需打开，禁止通读）

| 文件 | 何时看 |
|---|---|
| `references/00-overview.md` | 第一次做小程序项目，需要全流程 |
| `references/01-recon-and-unpack.md` | 取包路径、解密、解包失败排查 |
| `references/02-traffic-interception.md` | 抓不到包/证书/pinning |
| `references/03-auth-and-session.md` | 登录链路、session_key、手机号、越权矩阵 |
| `references/04-cloudbase-security.md` | 云函数/数据库/存储规则 |
| `references/05-open-capability-abuse.md` | 小程序码/URL Link/订阅/客服/支付/发货 |
| `references/06-vuln-catalog.md` | 43 类漏洞的触发/步骤/证据/误报 |
| `references/07-webview-plugin-worker.md` | web-view/H5/插件/Worker/跨小程序跳转/CPRF |
| `references/08-casebook.md` | 找突破口，看真实案例共性 |
| `references/09-checklists.md` | 信息收集/接口/云开发/支付/隐私五张清单 |
| `references/10-automation.md` | AST/污点/LLM/动态 auth matrix/去混淆 |
| `references/11-reporting.md` | 报告结构与 SRC 驳回原因 |
| `references/12-sources.md` | 官方文档/工具/研究来源 |

## 6. 完成自检

- [ ] AppID、包 SHA-256、解包工具与质量分已写入 `manifest.json`。
- [ ] 接口清单已 `insert_assets(type=endpoint)`，每条带来源。
- [ ] 密钥已 `record_fact`/`save_evidence`，值为脱敏。
- [ ] 云环境/函数/集合已登记并评估规则。
- [ ] 高价值页面（登录/支付/订单/地址/会员/上传）已覆盖。
- [ ] 越权矩阵至少覆盖：无 token、空 token、A→B、普通→管理、过期/伪造 token。
- [ ] 每条 finding 有源码行/请求响应/复现命令/影响/修复；high/critical 过 `evidence_check`。
- [ ] 包内文件名不安全/解包 `partial` 等限制已在报告中写明。
