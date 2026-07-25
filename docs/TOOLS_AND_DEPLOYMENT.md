# APK 安全分析工具 — 工具原理与部署清单

> 本文档梳理本套件的核心检测逻辑、用到的工具及其原理，并给出完整的部署依赖清单（外部工具 + 运行环境 + Python 依赖）。
> 适用于新环境部署、维护交接与二次开发参考。

---

## 一、整体架构

套件由 4 个 Python 脚本协作，完成「APK 静态解析 → 安装 → 后台抓包 → 运行时行为采集 → 流量解析 → 可视化报告 → 自动清理」的端到端自动化分析。

| 文件 | 职责 | 关键类/入口 |
|------|------|-------------|
| [apk_capture_final.py](file:///c:/Users/wangjie/Desktop/qume/demo/apk_capture_final.py) | 主脚本：全流程编排 | `ADBHelper` / `APKAnalyzer` / `PCAPdroidController` / `AppLauncher` / `AppTraverser` |
| [pcap_analyzer.py](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py) | PCAP 流量解析 | `PCAPAnalyzer` / `IPInfoProvider` |
| [report_generator.py](file:///c:/Users/wangjie/Desktop/qume/demo/report_generator.py) | HTML 报告生成 | `ReportGenerator` |
| [batch_analyze.py](file:///c:/Users/wangjie/Desktop/qume/demo/batch_analyze.py) | 批量分析入口 | `subprocess` 逐个调用主脚本 |

辅助文件：
- `PCAP.txt` — PCAPdroid 的 API Key（用于 Intent API 免 UI 控制抓包）
- `apk_input/` — 待分析 APK 存放目录
- `output/{APK名}_{时间戳}/` — 单次运行结果（pcap/json/html/截图）

---

## 二、端到端检测流程

主脚本 [apk_capture_final.py](file:///c:/Users/wangjie/Desktop/qume/demo/apk_capture_final.py) 的 `main()` 按以下 12 步执行：

### 步骤 1：设备检查
[`ADBHelper.check_device()`](file:///c:/Users/wangjie/Desktop/qume/demo/apk_capture_final.py#L73-L95) 执行 `adb devices`，校验唯一设备已连接，多设备时要求 `-s` 指定。

### 步骤 2：APK 静态解析（三路候选融合）
[`APKAnalyzer.get_package_info()`](file:///c:/Users/wangjie/Desktop/qume/demo/apk_capture_final.py#L372-L411) 采用**混淆感知 + 多方法融合**策略，并行收集三路候选后按置信度择优：

| 候选源 | 工具 | 适用场景 |
|--------|------|----------|
| androguard | 纯 Python `androguard.core.apk.APK` | 常规 APK，首选 |
| aapt | `aapt dump badging` (subprocess) | androguard 失败时备选 |
| 原始 Manifest | ZIP 解压 + 二进制 XML 正则 | 混淆/恶意 APK（子包数统计法） |

择优优先级（[`_select_best_candidate`](file:///c:/Users/wangjie/Desktop/qume/demo/apk_capture_final.py#L414-L467)）：
1. 非混淆包名 + 多方法一致 → 最高可信
2. 非混淆包名（单方法）→ `androguard > aapt > raw_manifest`
3. 全部混淆 → 用原始 Manifest（对混淆最鲁棒）
4. 全部为空 → 文件名兜底

同时提取：文件哈希（MD5/SHA256）、应用名、版本、最低/目标 SDK、申请权限列表、签名信息。

### 步骤 3：安装 APK + 真实包名差集检测
- 安装前清理所有候选包名的旧残留（避免差集污染）
- 记录安装前包名集合 `before_pkgs`（[`get_installed_packages`](file:///c:/Users/wangjie/Desktop/qume/demo/apk_capture_final.py#L110-L120)，`pm list packages`）
- `adb install -r` 安装
- **差集检测真实包名**（[`detect_installed_package`](file:///c:/Users/wangjie/Desktop/qume/demo/apk_capture_final.py#L122-L157)）：`after - before` 取系统 PackageManager 注册的真实包名，纠正静态解析（混淆 APK 静态包名常被篡改，系统 ground truth 最准）
- **查询系统真实 launcher activity**（[`get_launcher_activity`](file:///c:/Users/wangjie/Desktop/qume/demo/apk_capture_final.py#L159-L185)）：`cmd package resolve-activity --brief -c android.intent.category.LAUNCHER`

### 步骤 4：安全弹窗处理
`_close_security_dialogs_adb()`（ADB 按键）与 `_close_security_dialogs_ui()`（uiautomator2）双重保障：
- 风险提示弹窗 → 点击「继续使用」
- 风险管控中心弹窗 → 点击「取消」
- 仅在 APK 安装后、启动后处理；只处理系统弹窗，忽略其他元素

### 步骤 5：启动 PCAPdroid 抓包（纯 API，无 UI）
[`PCAPdroidController.start_capture()`](file:///c:/Users/wangjie/Desktop/qume/demo/apk_capture_final.py#L761-L816) 通过 PCAPdroid 官方 API 控制：

```bash
adb shell am start -e action start -e api_key KEY \
  -e pcap_dump_mode pcap_file -e pcap_name capture_xxx \
  -n com.emanuelef.remote_capture/.activities.CaptureCtrl
```

- 传入 `api_key`（从 `PCAP.txt` 读取）→ PCAPdroid 不弹权限确认，直接抓包
- **全局抓包模式**（不传 `app_filter`）— 实测 `app_filter` Intent 参数不稳定，全局更可靠
- 抓包在后台 VPN 隧道（tun0）运行，无需 PCAPdroid 在前台
- 停止：`-e action stop`

### 步骤 6：启动应用
[`AppLauncher.launch_app()`](file:///c:/Users/wangjie/Desktop/qume/demo/apk_capture_final.py#L1480-L1534)：
- `am start -n pkg/activity -a android.intent.action.MAIN -c android.intent.category.LAUNCHER`
- 失败兜底：[`_fallback_launch`](file:///c:/Users/wangjie/Desktop/qume/demo/apk_capture_final.py#L1541-L1557) 用 `monkey -p pkg -c android.intent.category.LAUNCHER 1`

### 步骤 7：反复启停循环 + 周期截图
`_run_app_with_cycles()` 按参数（默认 2 次启停，每次约 10 秒，每 10 秒截图）多次启停应用，采集不同运行阶段的网络行为与界面截图。

### 步骤 8：停止抓包 + 拉取 PCAP
`stop_capture()` → `adb pull` 把 PCAP 文件拉到输出目录。

### 步骤 9：流量解析
实例化 `PCAPAnalyzer` 解析 PCAP（详见第三节）。

### 步骤 10：生成报告
`ReportGenerator` 整合 APK 信息 + 截图 + 流量分析，生成统一通信记录表 HTML 报告（详见第四节）。

### 步骤 11：自动卸载
`adb uninstall` 卸载应用，保持设备清洁（项目硬约束）。

---

## 三、PCAP 流量解析原理（pcap_analyzer.py）

基于 **scapy** 解析 PCAP 文件，[`PCAPAnalyzer`](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py#L126) 逐包分发到各分析器：

| 分析器 | 提取内容 | 原理 |
|--------|----------|------|
| [`_analyze_dns`](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py#L275-L319) | 域名→IP 映射、CNAME 别名、时间戳 | scapy `DNS` 层，按 `qr` 区分查询/响应 |
| [`_analyze_ip`](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py#L328) | 源/目的 IP、端口、包数、流量、时间 | `IP` 层统计 |
| [`_analyze_tcp` / `_analyze_udp`](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py#L361) | TCP/UDP 流 | 五元组流聚合 |
| [`_analyze_http`](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py#L430-L491) | 明文 HTTP 完整 URL（方法+Host+Path） | 解析 TCP payload 请求行与 Host 头 |
| [`_analyze_tls_sni`](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py#L493-L512) | HTTPS 的 TLS SNI 域名 | 解析 TLS ClientHello 字节流（content_type=0x16） |

### DNS 应答类型处理（关键修复点）
scapy 对不同 DNS 记录类型的 `rdata` 返回不同 Python 类型，[`_extract_dns_answer`](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py#L246-L273) 按 Python 类型区分处理，避免 `str(bytes)` 产生 `b'xxx.'` 脏数据污染报告：

| DNS 记录 | scapy rdata 类型 | 处理 |
|----------|------------------|------|
| A / AAAA (type=1/28) | `str`（IP 字符串） | 归为 `ip`，计入 `ips` |
| CNAME / NS / PTR (type=5/2/12) | `bytes`（域名，带 FQDN 末尾点） | decode + 去末尾点，归为 `cname` |
| TXT (type=16) | `list[bytes]` | 非 IP 非域名，跳过 |

### IP 地理位置与云厂商识别
[`IPInfoProvider`](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py#L30-L123)：
- 调用 **ip-api.com** 免费 API（`http://ip-api.com/json/{ip}`，每分钟 45 次限制），结果带缓存
- [`_identify_cloud_provider`](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py#L57-L74) 基于 `org/isp/as` 字段关键字匹配 [`CLOUD_PROVIDER_RULES`](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py#L34-L52)：华为云、阿里云、腾讯云、AWS、中国移动/联通/电信、微软云、谷歌云、百度云、京东云、UCloud、金山云等

---

## 四、报告生成原理（report_generator.py）

[`ReportGenerator`](file:///c:/Users/wangjie/Desktop/qume/demo/report_generator.py) 整合三方数据生成可视化 HTML：

1. **APK 基本信息**：包名、版本、大小、哈希、权限、主 Activity（androguard 提供）
2. **运行截图**：Base64 编码内嵌（静态图片按 1KB~512KB 过滤，限 20 张）
3. **统一通信记录表**（[`_collect_unified_records`](file:///c:/Users/wangjie/Desktop/qume/demo/report_generator.py#L1081)）：以**域名为粒度**聚合所有来源数据为单表

| 列 | 数据来源 |
|----|----------|
| 域名 + CNAME 别名 | DNS 解析（CNAME 在域名下方小字 `↳` 展示） |
| 协议 | HTTP / HTTPS（TLS SNI） |
| 请求方法 | HTTP 方法 + TLS SNI |
| URL / 路径 | 明文 HTTP 完整 URL；HTTPS 标注「路径加密」 |
| DNS 解析 IP | A/AAAA 记录（完整不省略） |
| 地理位置 | ip-api.com（多 IP 去重合并） |
| 归属厂商 | 云厂商徽章（华为云红 / 阿里·腾讯·AWS 黄 / 运营商绿） |
| 请求次数 / 时间 | 各来源聚合，按首次请求时间排序 |

防御性清洗：[`_is_clean_ip`](file:///c:/Users/wangjie/Desktop/qume/demo/report_generator.py#L1094-L1105) 过滤历史 JSON 中可能残留的 `b'xxx.'` 脏字符串，确保兼容旧数据。

---

## 五、部署依赖清单

### 5.1 外部工具

| 工具 | 用途 | 来源 | 必需性 |
|------|------|------|--------|
| **adb** (Android Debug Bridge) | 设备通信、安装/启动/卸载/抓包控制 | Android Platform-Tools | 必需 |
| **aapt** (Android Asset Packaging Tool) | APK 静态解析备选（`dump badging`） | Android SDK build-tools | 可选（androguard 失败时兜底） |
| **PCAPdroid** | 设备端 VPN 抓包（com.emanuelef.remote_capture） | Google Play / GitHub Release | 必需，**v1.8.6+**（支持 api_key Intent） |
| **uiautomator2 ATX agent** | 设备端 UI 自动化（弹窗处理） | `python -m uiautomator2 init` 推送 | 必需 |

### 5.2 运行环境

| 项 | 要求 |
|----|------|
| 操作系统 | Windows / Linux / macOS（当前为 Windows 11） |
| Python | **3.8+**（用了类型注解 `tuple`、f-string、pathlib 等） |
| Android 设备 | Android 5.0+（API 21+），已开启 USB 调试并授权 |
| 网络 | 需访问 ip-api.com（IP 地理位置查询） |
| PCAPdroid API Key | 在设备 PCAPdroid → 设置 → 控制权限 → 生成 API Key，粘贴到 `PCAP.txt` |

### 5.3 Python 依赖

见 [requirements.txt](file:///c:/Users/wangjie/Desktop/qume/demo/requirements.txt)：

| 包 | 版本 | 用途 |
|----|------|------|
| `uiautomator2` | >=3.0.0 | Android UI 自动化（弹窗处理、截图、遍历） |
| `androguard` | >=3.4.0 | APK 静态解析（包名/Activity/权限/签名，纯 Python） |
| `scapy` | >=2.5.0 | PCAP 文件解析（DNS/HTTP/TLS/IP） |

> 注：IP 地理位置查询使用 Python 标准库 `urllib.request`，**无需额外安装 `requests`**（README 中提及 requests 系历史描述，实际未使用）。
> 注：scapy 在 Windows 无 libpcap 时会告警 `No libpcap provider available`，不影响 PCAP 离线解析（仅 `rdpcap` 读文件，不实时抓包）。

### 5.4 设备端准备步骤

1. 手机开启「开发者选项 → USB 调试」，USB 连接电脑，`adb devices` 确认授权
2. 安装 PCAPdroid v1.8.6+，打开一次完成初始化，生成 API Key 填入 `PCAP.txt`
3. 推送 uiautomator2 agent：`python -m uiautomator2 init`
4. 确认 aapt（如需）：设置 `ANDROID_HOME` 环境变量，[`_find_aapt`](file:///c:/Users/wangjie/Desktop/qume/demo/apk_capture_final.py#L297-L340) 会自动在 `build-tools/*/aapt.exe` 查找

### 5.5 一键安装

```bash
# Python 依赖
pip install -r requirements.txt

# 设备端 agent
python -m uiautomator2 init

# 验证
adb devices
python apk_capture_final.py -a apk_input/demo.apk
```

---

## 六、附：近期修复 — DNS bytes 数据处理

**问题**：报告中出现 `b'oss-acc-allline.aliyuncs.com.'` 这类带 `b'...'` 前缀和 FQDN 末尾点的脏数据。

**根因**：[`_analyze_dns`](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py#L275-L319) 原先对所有 DNS 应答统一 `str(answer.rdata)`：
- CNAME 记录 rdata 是 `bytes`，`str(bytes)` → `"b'xxx.'"` 脏字符串，被误当 IP 塞入 `ips`
- TXT 记录 rdata 是 `list[bytes]`，`str(list)` → `"[b'xxx']"` 同样污染

**修复**：
1. 新增 [`_extract_dns_answer`](file:///c:/Users/wangjie/Desktop/qume/demo/pcap_analyzer.py#L246-L273) 按 Python 类型区分 A/AAAA(IP) / CNAME(域名) / TXT(跳过)，bytes 统一 `decode + rstrip('.')`
2. CNAME 别名单独存入 `cnames` 字段，不再混入 `ips`
3. report_generator 加 [`_is_clean_ip`](file:///c:/Users/wangjie/Desktop/qume/demo/report_generator.py#L1094-L1105) 防御性清洗历史数据，并在域名下方展示 CNAME 别名链

**验证**：用真实 base.apk 流量回归，JSON 与 HTML 中 `b'...'` 残留均归零，5 个域名的 CNAME 别名正确提取与展示。
