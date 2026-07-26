#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Chrome APK 分发站点监控模块 - 通过 CDP 监听 Chrome 网络请求, 捕获带鉴权的 APK 下载链接

数据流: Chrome(--remote-debugging-port) → CDP事件 → APK识别 → CapturedRequest → ApkDownloader
"""

import json
import logging
import queue
import re
import threading
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

try:
    import websocket
    HAS_WEBSOCKET = True
except ImportError:
    HAS_WEBSOCKET = False
    websocket = None


APK_MIME_TYPES = {
    'application/vnd.android.package-archive',
    'application/octet-stream',
    'application/zip',
    'application/x-zip-compressed',
    'application/java-archive',
    'application/x-apk',
}

APK_KEYWORDS = ('apk', 'download', 'app', 'package')


class ChromeMonitorError(Exception):
    """Chrome 监控连接 / 通信异常"""


@dataclass
class CapturedRequest:
    """捕获到的 APK 下载请求"""
    url: str
    method: str
    request_headers: dict
    response_status: int = 0
    content_type: str = ''
    content_length: int = 0
    timestamp: str = ''
    request_id: str = ''

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


class ChromeMonitor:
    """通过 CDP 监控 Chrome 网络请求, 捕获 APK 下载链接"""

    def __init__(
        self,
        host: str = 'localhost',
        port: int = 9222,
        filter_url_patterns: Optional[list] = None,
    ):
        self.host = host
        self.port = port
        self.filter_url_patterns = filter_url_patterns or []
        self._ws = None
        self._thread = None
        self._stopped = threading.Event()
        self._captured_queue: queue.Queue = queue.Queue()
        self._pending_requests: dict = {}
        self._msg_id = 0

    def start(self) -> None:
        if not HAS_WEBSOCKET:
            raise ChromeMonitorError(
                "websocket-client 未安装, 请运行: pip install websocket-client"
            )
        ws_url = self._discover_target_ws_url()
        if not ws_url:
            raise ChromeMonitorError(
                f"未找到可用的 Chrome 调试目标 (host={self.host}, port={self.port})"
            )
        logger.info(f"连接 Chrome CDP: {ws_url}")
        try:
            self._ws = websocket.create_connection(ws_url, timeout=10)
        except Exception as e:
            raise ChromeMonitorError(f"WebSocket 连接失败: {e}") from e
        self._send_cdp('Network.enable')
        self._stopped.clear()
        self._thread = threading.Thread(target=self._event_loop, daemon=True)
        self._thread.start()
        logger.info("Chrome 网络监控已启动, 等待 APK 下载请求...")

    def stop(self) -> None:
        self._stopped.set()
        if self._ws:
            try:
                self._ws.close()
            except Exception:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=5)

    def wait_for_apk(self, timeout: int = 300) -> CapturedRequest:
        try:
            req = self._captured_queue.get(timeout=timeout)
            return req
        except queue.Empty:
            raise ChromeMonitorError(f"等待 APK 下载超时 ({timeout}s)")

    def wait_for_apks(self, count: int = 1, timeout: int = 300) -> list:
        results = []
        deadline = timeout
        for i in range(count):
            remaining = deadline - sum(
                0 for _ in results
            )
            if remaining <= 0:
                raise ChromeMonitorError(f"等待 APK 下载超时 ({timeout}s)")
            try:
                req = self._captured_queue.get(timeout=timeout)
                results.append(req)
            except queue.Empty:
                if len(results) < count:
                    raise ChromeMonitorError(
                        f"仅捕获到 {len(results)}/{count} 个 APK, 超时 ({timeout}s)"
                    )
        return results

    def close(self) -> None:
        self.stop()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def _discover_target_ws_url(self) -> Optional[str]:
        url = f'http://{self.host}:{self.port}/json'
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                targets = json.loads(resp.read().decode('utf-8'))
        except Exception as e:
            raise ChromeMonitorError(
                f"无法连接 Chrome 调试端口 ({url}): {e}\n"
                f"请确保 Chrome 以 --remote-debugging-port={self.port} 启动"
            ) from e
        for target in targets:
            if target.get('type') == 'page':
                ws_url = target.get('webSocketDebuggerUrl')
                if ws_url:
                    return ws_url
        return None

    def _send_cdp(self, method: str, params: Optional[dict] = None) -> int:
        self._msg_id += 1
        msg = {
            'id': self._msg_id,
            'method': method,
            'params': params or {},
        }
        if self._ws:
            self._ws.send(json.dumps(msg))
        return self._msg_id

    def _event_loop(self) -> None:
        while not self._stopped.is_set():
            try:
                raw = self._ws.recv()
                if not raw:
                    continue
                event = json.loads(raw)
                self._handle_event(event)
            except ConnectionResetError:
                logger.warning("Chrome 连接已断开")
                break
            except Exception as e:
                if self._stopped.is_set():
                    break
                logger.debug(f"事件循环异常: {e}")

    def _handle_event(self, event: dict) -> None:
        method = event.get('method', '')
        params = event.get('params', {})
        if method == 'Network.requestWillBeSent':
            self._on_request_will_be_sent(params)
        elif method == 'Network.responseReceived':
            self._on_response_received(params)

    def _on_request_will_be_sent(self, params: dict) -> None:
        req_id = params.get('requestId', '')
        request = params.get('request', {})
        url = request.get('url', '')
        method = request.get('method', 'GET')
        headers = request.get('headers', {})
        self._pending_requests[req_id] = {
            'url': url,
            'method': method,
            'request_headers': headers,
            'request_id': req_id,
        }

    def _on_response_received(self, params: dict) -> None:
        req_id = params.get('requestId', '')
        response = params.get('response', {})
        mime_type = response.get('mimeType', '')
        status = response.get('status', 0)
        resp_headers = response.get('headers', {})
        encoded_length = response.get('encodedDataLength', 0)
        pending = self._pending_requests.pop(req_id, None)
        if not pending:
            return
        url = pending['url']
        if not self._is_apk_request(url, mime_type):
            return
        if self.filter_url_patterns:
            if not any(re.search(p, url) for p in self.filter_url_patterns):
                return
        captured = CapturedRequest(
            url=url,
            method=pending['method'],
            request_headers=pending['request_headers'],
            response_status=status,
            content_type=mime_type,
            content_length=encoded_length,
            request_id=req_id,
        )
        size_mb = encoded_length / (1024 * 1024) if encoded_length else 0
        logger.info(
            f"捕获到 APK 下载请求: {url[:80]}{'...' if len(url) > 80 else ''} "
            f"({size_mb:.1f} MB, {mime_type})"
        )
        self._captured_queue.put(captured)

    @staticmethod
    def _is_apk_request(url: str, mime_type: str) -> bool:
        path = url.split('?')[0].split('#')[0].lower()
        if path.endswith('.apk'):
            return True
        if mime_type == 'application/vnd.android.package-archive':
            return True
        if mime_type in ('application/octet-stream', 'application/zip', 'application/x-zip-compressed'):
            return any(kw in path for kw in ('apk', 'download'))
        if mime_type == 'application/java-archive':
            return 'apk' in path
        return False
