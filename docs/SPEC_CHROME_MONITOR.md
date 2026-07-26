# SPEC: Chrome APK 分发站点监控模块

> Issue: [#2 支持通过Chrome监控APK分发站点上分发的APK](https://github.com/russellwj/ApkDynamicDetectTool/issues/2)
> 状态: Draft
> 开发模式: SDD (Specification-Driven Development)

---

## 1. 概述

### 1.1 需求背景

许多 APK 分发站点使用动态鉴权机制:
- 下载链接带短时效 token (如 `?token=abc&exp=1234567890`)
- 需要登录 Cookie 才能下载
- 签名链接有过期时间
- 需要特定的 Referer / Origin 头

当前 `ApkDownloader` 仅支持静态 URL 下载, 无法携带鉴权信息。直接从浏览器复制的 URL 在过期后无法下载, 或因缺少 Cookie 而返回 403。

### 1.2 目标

通过 Chrome DevTools Protocol (CDP) 连接用户已打开的 Chrome 浏览器, 实时监听网络请求, 捕获 APK 下载链接及其完整的请求头 (Cookie / Authorization / Referer 等), 将鉴权信息传递给 `ApkDownloader` 完成下载, 并自动触发后续分析流程。

### 1.3 用户场景

```
用户操作流程:
1. 启动 Chrome (带 --remote-debugging-port=9222)
2. 运行: python main/apk_capture_final.py --monitor
3. 工具提示: "正在监听 Chrome 网络请求, 等待 APK 下载..."
4. 用户在 Chrome 中登录分发站点, 点击下载按钮
5. 工具自动捕获下载 URL + Cookie + Token
6. 工具提示: "捕获到 APK: app.apk (15.2 MB), 开始下载..."
7. 工具使用捕获的鉴权信息下载 APK
8. 工具自动执行安装→抓包→分析→报告→卸载
```

---

## 2. 功能规格

### 2.1 F1: Chrome CDP 连接

| 编号 | 规格 |
|------|------|
| F1.1 | 通过 HTTP `http://localhost:{port}/json` 发现 Chrome 调试目标 (targets) |
| F1.2 | 连接到指定 target 的 WebSocket 调试 URL (`webSocketDebuggerUrl`) |
| F1.3 | 支持连接已有 Chrome 实例 (用户已手动启动) |
| F1.4 | 连接失败时给出明确的错误提示 (Chrome 未启动 / 端口被占用 / 无可用 target) |
| F1.5 | 支持 `host` 和 `port` 参数自定义 (默认 localhost:9222) |

### 2.2 F2: 网络请求监听

| 编号 | 规格 |
|------|------|
| F2.1 | 通过 CDP `Network.enable` 开启网络事件监听 |
| F2.2 | 监听 `Network.requestWillBeSent` 事件获取: URL / method / requestHeaders |
| F2.3 | 监听 `Network.responseReceived` 事件获取: mimeType / status / headers / contentLength |
| F2.4 | 事件循环运行在后台线程, 不阻塞主线程 |
| F2.5 | 支持超时控制 (等待 N 秒无 APK 下载则超时退出) |

### 2.3 F3: APK 下载请求识别

识别规则 (满足任一即为 APK 下载请求):

| 编号 | 规则 | 优先级 |
|------|------|--------|
| F3.1 | URL 路径以 `.apk` 结尾 (忽略 query / fragment) | 高 |
| F3.2 | Response mimeType = `application/vnd.android.package-archive` | 高 |
| F3.3 | Response mimeType = `application/octet-stream` 且 URL 包含 `apk` 关键词 | 中 |
| F3.4 | Response mimeType = `application/zip` 且 URL 包含 `apk` / `download` 关键词 | 中 |
| F3.5 | Response mimeType = `application/java-archive` 且 URL 包含 `apk` 关键词 | 中 |

非 APK 请求 (如 HTML / JS / CSS / 图片) 一律忽略。

### 2.4 F4: 鉴权信息捕获

| 编号 | 规格 |
|------|------|
| F4.1 | 捕获完整的请求头字典 (含 Cookie / Authorization / Referer / User-Agent 等) |
| F4.2 | 将捕获的请求头传递给 `ApkDownloader.download(url, headers=captured_headers)` |
| F4.3 | ApkDownloader 在下载时将自定义头覆盖到 urllib Request 上 |
| F4.4 | 保留 ApkDownloader 自身的 User-Agent (除非捕获头中包含 User-Agent) |

### 2.5 F5: 自动化分析流程集成

| 编号 | 规格 |
|------|------|
| F5.1 | `capture_pipeline.py` 新增 `--monitor` 参数 (与 `-a` / `--url` 三选一互斥) |
| F5.2 | `batch_analyze.py` 新增 `--monitor` 参数 |
| F5.3 | `--monitor` 模式下, 捕获到 APK 后自动下载并替换 `args.apk` |
| F5.4 | `--monitor-timeout` 参数控制等待超时 (默认 300 秒) |
| F5.5 | `--monitor-count` 参数控制等待 APK 数量 (batch_analyze, 默认 1) |

---

## 3. 接口定义

### 3.1 数据结构

```python
@dataclass
class CapturedRequest:
    url: str                      # APK 下载 URL (含 query 参数)
    method: str                   # HTTP 方法 (GET / POST)
    request_headers: dict         # 请求头 (Cookie / Authorization / Referer ...)
    response_status: int          # HTTP 响应状态码
    content_type: str             # Response Content-Type / mimeType
    content_length: int           # Response Content-Length (字节)
    timestamp: datetime           # 捕获时间
    request_id: str               # CDP request_id (用于去重)
```

### 3.2 异常

```python
class ChromeMonitorError(Exception):
    """Chrome 监控连接 / 通信异常"""
```

### 3.3 ChromeMonitor 类

```python
class ChromeMonitor:
    """通过 CDP 监控 Chrome 网络请求, 捕获 APK 下载链接"""

    def __init__(
        self,
        host: str = 'localhost',
        port: int = 9222,
        filter_url_patterns: list = None,
    ):
        """
        Args:
            host: Chrome 远程调试地址
            port: Chrome 远程调试端口
            filter_url_patterns: URL 额外过滤正则列表 (None 则不过滤)
        """

    def start(self) -> None:
        """启动 Chrome CDP 连接和网络监听 (非阻塞, 后台线程运行)"""

    def stop(self) -> None:
        """停止监听, 关闭 WebSocket 连接"""

    def wait_for_apk(
        self,
        timeout: int = 300,
    ) -> CapturedRequest:
        """
        阻塞等待一个 APK 下载请求被捕获

        Args:
            timeout: 超时秒数

        Returns:
            CapturedRequest

        Raises:
            ChromeMonitorError: 超时 / 连接断开
        """

    def wait_for_apks(
        self,
        count: int = 1,
        timeout: int = 300,
    ) -> list:
        """
        阻塞等待多个 APK 下载请求

        Args:
            count: 期望捕获的 APK 数量
            timeout: 总超时秒数

        Returns:
            CapturedRequest 列表
        """

    def close(self) -> None:
        """清理资源"""

    # 可作为 context manager 使用
    def __enter__(self): return self
    def __exit__(self, *args): self.close()
```

### 3.4 ApkDownloader 扩展

```python
class ApkDownloader:
    def download(
        self,
        url: str,
        filename: Optional[str] = None,
        headers: Optional[dict] = None,  # 新增: 自定义请求头
    ) -> Path: ...

    def _download_file(
        self,
        url: str,
        dest: Path,
        headers: Optional[dict] = None,  # 新增
    ) -> None: ...
```

### 3.5 CLI 参数

| 工具 | 参数 | 说明 | 默认值 |
|------|------|------|--------|
| capture_pipeline | `--monitor` | 启动 Chrome 监控模式 | False |
| capture_pipeline | `--monitor-port` | Chrome 调试端口 | 9222 |
| capture_pipeline | `--monitor-timeout` | 监控超时秒数 | 300 |
| batch_analyze | `--monitor` | 启动 Chrome 监控模式 | False |
| batch_analyze | `--monitor-port` | Chrome 调试端口 | 9222 |
| batch_analyze | `--monitor-timeout` | 监控超时秒数 | 300 |
| batch_analyze | `--monitor-count` | 等待捕获 APK 数量 | 1 |

---

## 4. 技术方案

### 4.1 依赖

| 库 | 用途 | 是否可选 |
|----|------|----------|
| `websocket-client` | CDP WebSocket 通信 | 可选 (与 uiautomator2 共存) |

`websocket-client` 与 `uiautomator2` 生态兼容 (u2 内部也使用 websocket)。
若未安装, `chrome_monitor` 模块导入时给出提示。

### 4.2 CDP 协议交互

```
1. HTTP GET http://localhost:9222/json
   → JSON 数组, 每个 target 含 {id, type, url, title, webSocketDebuggerUrl}

2. 选择 type="page" 的 target, 取其 webSocketDebuggerUrl

3. WebSocket 连接到 webSocketDebuggerUrl

4. 发送 CDP 命令:
   {"id": 1, "method": "Network.enable", "params": {}}

5. 接收事件 (后台线程循环):
   {"method": "Network.requestWillBeSent", "params": {requestId, request:{url, method, headers}, ...}}
   {"method": "Network.responseReceived", "params": {requestId, response:{mimeType, status, headers, encodedDataLength}, ...}}

6. 按 requestId 关联 request 和 response

7. 匹配 APK 识别规则 → 生成 CapturedRequest → 放入队列
```

### 4.3 APK 识别算法

```python
def _is_apk_request(self, url: str, mime_type: str) -> bool:
    path = url.split('?')[0].split('#')[0].lower()
    if path.endswith('.apk'):
        return True
    if mime_type == 'application/vnd.android.package-archive':
        return True
    if mime_type in ('application/octet-stream', 'application/zip'):
        return 'apk' in path or 'download' in path
    if mime_type == 'application/java-archive':
        return 'apk' in path
    return False
```

### 4.4 线程模型

```
主线程:
  ChromeMonitor.start()  → 启动后台线程, 立即返回
  ChromeMonitor.wait_for_apk()  → 阻塞等待 queue.get(timeout)

后台线程 (事件循环):
  while not stopped:
    recv() CDP 事件
    parse → match APK → put CapturedRequest to queue
```

### 4.5 模块依赖关系

```
chrome_monitor.py ──── websocket (CDP 通信)
       │
       ↓ produces
  CapturedRequest (url + headers)
       │
       ↓ feeds
  apk_downloader.py ──── urllib (HTTP 下载)
       │
       ↓ produces
  local .apk file
       │
       ↓ feeds
  capture_pipeline.py / batch_analyze.py
```

---

## 5. 测试规格

### 5.1 测试模块

`tests/test_chrome_monitor.py`

### 5.2 测试矩阵

| 测试类 | 覆盖目标 | 用例数 |
|--------|----------|--------|
| TestIsApkRequest | APK 识别算法 (URL + mimeType 组合) | 12 |
| TestCapturedRequest | 数据结构字段与序列化 | 4 |
| TestDiscoverTargets | HTTP 发现 Chrome targets (mock urllib) | 5 |
| TestCdpConnect | WebSocket 连接与 CDP 命令发送 (mock websocket) | 6 |
| TestEventParsing | CDP 事件 JSON → CapturedRequest (request+response 关联) | 8 |
| TestWaitForApk | 阻塞等待 + 超时 + 队列交互 (mock 内部队列) | 5 |
| TestWaitForApks | 多个 APK 等待 + 提前完成 + 超时 | 4 |
| TestApkDownloaderHeaders | ApkDownloader.download 接受 headers 参数 | 6 |
| TestPipelineMonitorIntegration | capture_pipeline --monitor 参数解析 | 3 |
| TestBatchAnalyzeMonitorIntegration | batch_analyze --monitor 参数解析 | 3 |
| **合计** | | **56** |

### 5.3 Mock 策略

| 依赖 | Mock 方式 |
|------|-----------|
| `urllib.request.urlopen` | 返回 fake JSON / WebSocket URL |
| `websocket.WebSocket` | `MagicMock` 模拟 send/recv |
| `threading.Thread` | 不 mock, 用短超时测试 |
| `queue.Queue` | 直接用真实 Queue, 手动 put |

---

## 6. 验收标准

- [ ] 能连接 Chrome 并监听网络请求 (CDP Network.enable)
- [ ] 能识别 APK 下载请求 (URL 模式 + mimeType)
- [ ] 能捕获完整请求头 (Cookie / Authorization / Referer)
- [ ] 能将鉴权头传递给 ApkDownloader 并成功下载
- [ ] `--monitor` 参数在 capture_pipeline 和 batch_analyze 中可用
- [ ] `--monitor` 与 `-a` / `--url` 三选一互斥
- [ ] 超时机制正常工作
- [ ] 单元测试 56 个全部通过
- [ ] 总测试数 182 + 56 = 238 全部通过
- [ ] 无新增 import warning

---

## 7. 文件清单

| 文件 | 操作 |
|------|------|
| `apk_dynamic_tool/chrome_monitor.py` | 新建 |
| `apk_dynamic_tool/apk_downloader.py` | 修改 (添加 headers 参数) |
| `apk_dynamic_tool/capture_pipeline.py` | 修改 (添加 --monitor 参数) |
| `apk_dynamic_tool/__init__.py` | 修改 (导出 ChromeMonitor 等) |
| `main/batch_analyze.py` | 修改 (添加 --monitor 参数) |
| `tests/test_chrome_monitor.py` | 新建 |
| `config/requirements.txt` | 修改 (添加 websocket-client) |
| `README.md` | 修改 (补充文档) |

---

## 8. 开发顺序 (SDD 流程)

1. ✅ 编写本规格文档
2. ⬜ 实现 `chrome_monitor.py` 模块骨架 + 接口
3. ⬜ 修改 `apk_downloader.py` 添加 headers 支持
4. ⬜ 编写 `tests/test_chrome_monitor.py` 全部测试用例
5. ⬜ 实现填充逻辑直到全部测试通过
6. ⬜ 集成 `capture_pipeline.py` 和 `batch_analyze.py`
7. ⬜ 更新 `__init__.py` / `requirements.txt` / `README.md`
8. ⬜ 运行全部测试验证
9. ⬜ 提交并创建 PR
