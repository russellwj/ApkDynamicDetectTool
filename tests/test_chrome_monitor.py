#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""chrome_monitor 单元测试 - CDP 网络监控 APK 捕获"""

import sys
import json
import unittest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock
from dataclasses import dataclass

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apk_dynamic_tool.chrome_monitor import (
    ChromeMonitor,
    ChromeMonitorError,
    CapturedRequest,
)
from apk_dynamic_tool.apk_downloader import ApkDownloader, ApkDownloadError, APK_MAGIC


def _make_fake_apk_bytes(size_kb: int = 4) -> bytes:
    return APK_MAGIC + b'\x00' * (size_kb * 1024 - 4)


class _FakeResponse:
    def __init__(self, data: bytes, content_type: str = 'application/vnd.android.package-archive'):
        self._data = data
        self._pos = 0
        self.headers = {
            'Content-Length': str(len(data)),
            'Content-Type': content_type,
        }

    def read(self, size: int = -1):
        if size < 0 or size > len(self._data) - self._pos:
            chunk = self._data[self._pos:]
            self._pos = len(self._data)
        else:
            chunk = self._data[self._pos:self._pos + size]
            self._pos += size
        return chunk

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


class TestIsApkRequest(unittest.TestCase):
    """ChromeMonitor._is_apk_request: APK 识别算法"""

    def test_url_ends_with_apk(self):
        self.assertTrue(ChromeMonitor._is_apk_request(
            'https://example.com/app.apk', 'application/octet-stream'
        ))

    def test_url_ends_with_apk_with_query(self):
        self.assertTrue(ChromeMonitor._is_apk_request(
            'https://example.com/app.apk?token=abc&exp=123', 'application/octet-stream'
        ))

    def test_url_ends_with_apk_with_fragment(self):
        self.assertTrue(ChromeMonitor._is_apk_request(
            'https://example.com/app.apk#section', 'application/octet-stream'
        ))

    def test_mime_android_package_archive(self):
        self.assertTrue(ChromeMonitor._is_apk_request(
            'https://example.com/download?id=123', 'application/vnd.android.package-archive'
        ))

    def test_octet_stream_with_apk_keyword(self):
        self.assertTrue(ChromeMonitor._is_apk_request(
            'https://example.com/get_apk?id=123', 'application/octet-stream'
        ))

    def test_octet_stream_with_download_keyword(self):
        self.assertTrue(ChromeMonitor._is_apk_request(
            'https://example.com/download?id=123', 'application/octet-stream'
        ))

    def test_octet_stream_without_keywords(self):
        self.assertFalse(ChromeMonitor._is_apk_request(
            'https://example.com/file?id=123', 'application/octet-stream'
        ))

    def test_zip_with_apk_keyword(self):
        self.assertTrue(ChromeMonitor._is_apk_request(
            'https://example.com/myapk.zip', 'application/zip'
        ))

    def test_zip_without_keywords(self):
        self.assertFalse(ChromeMonitor._is_apk_request(
            'https://example.com/archive.zip', 'application/zip'
        ))

    def test_java_archive_with_apk_keyword(self):
        self.assertTrue(ChromeMonitor._is_apk_request(
            'https://example.com/apk_file', 'application/java-archive'
        ))

    def test_java_archive_without_apk_keyword(self):
        self.assertFalse(ChromeMonitor._is_apk_request(
            'https://example.com/game.jar', 'application/java-archive'
        ))

    def test_html_mime_not_apk(self):
        self.assertFalse(ChromeMonitor._is_apk_request(
            'https://example.com/page.html', 'text/html'
        ))


class TestCapturedRequest(unittest.TestCase):
    """CapturedRequest: 数据结构"""

    def test_fields_set_correctly(self):
        req = CapturedRequest(
            url='https://example.com/app.apk',
            method='GET',
            request_headers={'Cookie': 'session=abc'},
            response_status=200,
            content_type='application/vnd.android.package-archive',
            content_length=1024,
            request_id='req-1',
        )
        self.assertEqual(req.url, 'https://example.com/app.apk')
        self.assertEqual(req.method, 'GET')
        self.assertEqual(req.request_headers['Cookie'], 'session=abc')
        self.assertEqual(req.response_status, 200)
        self.assertEqual(req.content_length, 1024)

    def test_timestamp_auto_generated(self):
        req = CapturedRequest(
            url='https://example.com/app.apk',
            method='GET',
            request_headers={},
        )
        self.assertTrue(req.timestamp)

    def test_request_headers_preserved(self):
        headers = {
            'Cookie': 'session=abc; token=xyz',
            'Authorization': 'Bearer abc123',
            'Referer': 'https://example.com/',
        }
        req = CapturedRequest(
            url='https://example.com/app.apk',
            method='GET',
            request_headers=headers,
        )
        self.assertEqual(req.request_headers, headers)

    def test_default_values(self):
        req = CapturedRequest(
            url='', method='', request_headers={}
        )
        self.assertEqual(req.response_status, 0)
        self.assertEqual(req.content_type, '')
        self.assertEqual(req.content_length, 0)
        self.assertEqual(req.request_id, '')


class TestDiscoverTargets(unittest.TestCase):
    """ChromeMonitor._discover_target_ws_url: HTTP 发现 Chrome targets"""

    @patch('apk_dynamic_tool.chrome_monitor.urllib.request.urlopen')
    def test_returns_ws_url_for_page_target(self, mock_urlopen):
        targets = [
            {'type': 'page', 'webSocketDebuggerUrl': 'ws://localhost:9222/devtools/page/abc'},
        ]
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(targets).encode()

        monitor = ChromeMonitor()
        ws_url = monitor._discover_target_ws_url()
        self.assertEqual(ws_url, 'ws://localhost:9222/devtools/page/abc')

    @patch('apk_dynamic_tool.chrome_monitor.urllib.request.urlopen')
    def test_returns_none_when_no_page_targets(self, mock_urlopen):
        targets = [
            {'type': 'background_page', 'webSocketDebuggerUrl': 'ws://localhost:9222/devtools/bg/1'},
        ]
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(targets).encode()

        monitor = ChromeMonitor()
        ws_url = monitor._discover_target_ws_url()
        self.assertIsNone(ws_url)

    @patch('apk_dynamic_tool.chrome_monitor.urllib.request.urlopen')
    def test_returns_none_when_empty_targets(self, mock_urlopen):
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value.__enter__.return_value.read.return_value = b'[]'

        monitor = ChromeMonitor()
        ws_url = monitor._discover_target_ws_url()
        self.assertIsNone(ws_url)

    @patch('apk_dynamic_tool.chrome_monitor.urllib.request.urlopen')
    def test_raises_on_connection_failure(self, mock_urlopen):
        mock_urlopen.side_effect = ConnectionRefusedError('Connection refused')

        monitor = ChromeMonitor(port=9999)
        with self.assertRaises(ChromeMonitorError) as ctx:
            monitor._discover_target_ws_url()
        self.assertIn('9999', str(ctx.exception))

    @patch('apk_dynamic_tool.chrome_monitor.urllib.request.urlopen')
    def test_ignores_non_page_targets(self, mock_urlopen):
        targets = [
            {'type': 'service_worker', 'webSocketDebuggerUrl': 'ws://localhost:9222/sw/1'},
            {'type': 'page', 'webSocketDebuggerUrl': 'ws://localhost:9222/page/1'},
        ]
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=MagicMock())
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value.__enter__.return_value.read.return_value = json.dumps(targets).encode()

        monitor = ChromeMonitor()
        ws_url = monitor._discover_target_ws_url()
        self.assertEqual(ws_url, 'ws://localhost:9222/page/1')


class TestCdpConnect(unittest.TestCase):
    """ChromeMonitor: WebSocket 连接与 CDP 命令发送"""

    def setUp(self):
        self._old_ws = sys.modules.get('apk_dynamic_tool.chrome_monitor')

    @patch('apk_dynamic_tool.chrome_monitor.HAS_WEBSOCKET', True)
    @patch('apk_dynamic_tool.chrome_monitor.websocket')
    @patch.object(ChromeMonitor, '_discover_target_ws_url')
    def test_start_sends_network_enable(self, mock_discover, mock_ws):
        mock_discover.return_value = 'ws://localhost:9222/devtools/page/abc'
        mock_ws.create_connection.return_value = MagicMock()

        monitor = ChromeMonitor()
        monitor.start()
        sent_msgs = [json.loads(c[0][0]) for c in mock_ws.create_connection.return_value.send.call_args_list]
        self.assertTrue(any(m['method'] == 'Network.enable' for m in sent_msgs))
        monitor.stop()

    @patch('apk_dynamic_tool.chrome_monitor.HAS_WEBSOCKET', True)
    @patch('apk_dynamic_tool.chrome_monitor.websocket')
    @patch.object(ChromeMonitor, '_discover_target_ws_url')
    def test_start_starts_background_thread(self, mock_discover, mock_ws):
        mock_discover.return_value = 'ws://localhost:9222/devtools/page/abc'
        mock_ws.create_connection.return_value = MagicMock()

        monitor = ChromeMonitor()
        monitor.start()
        self.assertIsNotNone(monitor._thread)
        self.assertTrue(monitor._thread.is_alive() or monitor._stopped.is_set())
        monitor.stop()

    @patch('apk_dynamic_tool.chrome_monitor.HAS_WEBSOCKET', False)
    def test_start_raises_without_websocket(self):
        monitor = ChromeMonitor()
        with self.assertRaises(ChromeMonitorError) as ctx:
            monitor.start()
        self.assertIn('websocket-client', str(ctx.exception))

    @patch('apk_dynamic_tool.chrome_monitor.HAS_WEBSOCKET', True)
    @patch('apk_dynamic_tool.chrome_monitor.websocket')
    @patch.object(ChromeMonitor, '_discover_target_ws_url')
    def test_start_raises_if_no_target_found(self, mock_discover, mock_ws):
        mock_discover.return_value = None

        monitor = ChromeMonitor()
        with self.assertRaises(ChromeMonitorError) as ctx:
            monitor.start()
        self.assertIn('未找到', str(ctx.exception))

    @patch('apk_dynamic_tool.chrome_monitor.HAS_WEBSOCKET', True)
    @patch('apk_dynamic_tool.chrome_monitor.websocket')
    @patch.object(ChromeMonitor, '_discover_target_ws_url')
    def test_stop_closes_websocket(self, mock_discover, mock_ws):
        mock_discover.return_value = 'ws://localhost:9222/devtools/page/abc'
        mock_ws_conn = MagicMock()
        mock_ws.create_connection.return_value = mock_ws_conn

        monitor = ChromeMonitor()
        monitor.start()
        monitor.stop()
        mock_ws_conn.close.assert_called_once()

    @patch('apk_dynamic_tool.chrome_monitor.HAS_WEBSOCKET', True)
    @patch('apk_dynamic_tool.chrome_monitor.websocket')
    @patch.object(ChromeMonitor, '_discover_target_ws_url')
    def test_send_cdp_increments_msg_id(self, mock_discover, mock_ws):
        mock_discover.return_value = 'ws://localhost:9222/devtools/page/abc'
        mock_ws.create_connection.return_value = MagicMock()

        monitor = ChromeMonitor()
        monitor.start()
        id1 = monitor._send_cdp('Page.enable')
        id2 = monitor._send_cdp('Runtime.enable')
        self.assertEqual(id2, id1 + 1)
        monitor.stop()


class TestEventParsing(unittest.TestCase):
    """ChromeMonitor: CDP 事件 JSON -> CapturedRequest"""

    def test_request_will_be_sent_stores_pending(self):
        monitor = ChromeMonitor()
        monitor._on_request_will_be_sent({
            'requestId': 'req-1',
            'request': {
                'url': 'https://example.com/app.apk',
                'method': 'GET',
                'headers': {'Cookie': 'session=abc'},
            }
        })
        self.assertIn('req-1', monitor._pending_requests)
        self.assertEqual(
            monitor._pending_requests['req-1']['url'],
            'https://example.com/app.apk'
        )

    def test_response_received_captures_apk_url(self):
        monitor = ChromeMonitor()
        monitor._on_request_will_be_sent({
            'requestId': 'req-1',
            'request': {
                'url': 'https://example.com/app.apk',
                'method': 'GET',
                'headers': {'Cookie': 'session=abc'},
            }
        })
        monitor._on_response_received({
            'requestId': 'req-1',
            'response': {
                'mimeType': 'application/octet-stream',
                'status': 200,
                'headers': {},
                'encodedDataLength': 4096,
            }
        })
        captured = monitor._captured_queue.get_nowait()
        self.assertEqual(captured.url, 'https://example.com/app.apk')
        self.assertEqual(captured.response_status, 200)
        self.assertEqual(captured.content_length, 4096)

    def test_response_received_captures_apk_mimetype(self):
        monitor = ChromeMonitor()
        monitor._on_request_will_be_sent({
            'requestId': 'req-2',
            'request': {
                'url': 'https://example.com/download?id=123',
                'method': 'GET',
                'headers': {'Authorization': 'Bearer xyz'},
            }
        })
        monitor._on_response_received({
            'requestId': 'req-2',
            'response': {
                'mimeType': 'application/vnd.android.package-archive',
                'status': 200,
                'headers': {},
                'encodedDataLength': 8192,
            }
        })
        captured = monitor._captured_queue.get_nowait()
        self.assertEqual(captured.url, 'https://example.com/download?id=123')
        self.assertEqual(captured.request_headers['Authorization'], 'Bearer xyz')

    def test_non_apk_response_ignored(self):
        monitor = ChromeMonitor()
        monitor._on_request_will_be_sent({
            'requestId': 'req-3',
            'request': {
                'url': 'https://example.com/page.html',
                'method': 'GET',
                'headers': {},
            }
        })
        monitor._on_response_received({
            'requestId': 'req-3',
            'response': {
                'mimeType': 'text/html',
                'status': 200,
                'headers': {},
                'encodedDataLength': 1024,
            }
        })
        self.assertTrue(monitor._captured_queue.empty())

    def test_request_without_response_not_captured(self):
        monitor = ChromeMonitor()
        monitor._on_request_will_be_sent({
            'requestId': 'req-4',
            'request': {
                'url': 'https://example.com/app.apk',
                'method': 'GET',
                'headers': {},
            }
        })
        self.assertTrue(monitor._captured_queue.empty())

    def test_multiple_requests_tracked_by_id(self):
        monitor = ChromeMonitor()
        for i in range(3):
            monitor._on_request_will_be_sent({
                'requestId': f'req-{i}',
                'request': {
                    'url': f'https://example.com/app{i}.apk',
                    'method': 'GET',
                    'headers': {},
                }
            })
        self.assertEqual(len(monitor._pending_requests), 3)
        monitor._on_response_received({
            'requestId': 'req-1',
            'response': {
                'mimeType': 'application/octet-stream',
                'status': 200,
                'headers': {},
                'encodedDataLength': 4096,
            }
        })
        captured = monitor._captured_queue.get_nowait()
        self.assertEqual(captured.url, 'https://example.com/app1.apk')

    def test_filter_url_patterns_applied(self):
        monitor = ChromeMonitor(filter_url_patterns=[r'example\.com'])
        monitor._on_request_will_be_sent({
            'requestId': 'req-5',
            'request': {
                'url': 'https://other.com/app.apk',
                'method': 'GET',
                'headers': {},
            }
        })
        monitor._on_response_received({
            'requestId': 'req-5',
            'response': {
                'mimeType': 'application/vnd.android.package-archive',
                'status': 200,
                'headers': {},
                'encodedDataLength': 4096,
            }
        })
        self.assertTrue(monitor._captured_queue.empty())

    def test_captured_request_has_correct_headers(self):
        monitor = ChromeMonitor()
        headers = {
            'Cookie': 'session=abc; token=xyz',
            'Authorization': 'Bearer secret',
            'Referer': 'https://example.com/',
            'X-Custom': 'value',
        }
        monitor._on_request_will_be_sent({
            'requestId': 'req-6',
            'request': {
                'url': 'https://example.com/app.apk',
                'method': 'GET',
                'headers': headers,
            }
        })
        monitor._on_response_received({
            'requestId': 'req-6',
            'response': {
                'mimeType': 'application/vnd.android.package-archive',
                'status': 200,
                'headers': {},
                'encodedDataLength': 4096,
            }
        })
        captured = monitor._captured_queue.get_nowait()
        self.assertEqual(captured.request_headers, headers)


class TestWaitForApk(unittest.TestCase):
    """ChromeMonitor.wait_for_apk: 阻塞等待"""

    def test_returns_captured_request(self):
        monitor = ChromeMonitor()
        req = CapturedRequest(
            url='https://example.com/app.apk',
            method='GET',
            request_headers={},
        )
        monitor._captured_queue.put(req)
        result = monitor.wait_for_apk(timeout=1)
        self.assertEqual(result.url, 'https://example.com/app.apk')

    def test_raises_on_timeout(self):
        monitor = ChromeMonitor()
        with self.assertRaises(ChromeMonitorError) as ctx:
            monitor.wait_for_apk(timeout=0.1)
        self.assertIn('超时', str(ctx.exception))

    def test_queue_is_thread_safe(self):
        import threading
        monitor = ChromeMonitor()
        results = []

        def producer():
            import time
            time.sleep(0.05)
            monitor._captured_queue.put(CapturedRequest(
                url='https://example.com/app.apk',
                method='GET',
                request_headers={},
            ))

        t = threading.Thread(target=producer)
        t.start()
        result = monitor.wait_for_apk(timeout=2)
        t.join()
        self.assertEqual(result.url, 'https://example.com/app.apk')

    def test_multiple_captures_queue_up(self):
        monitor = ChromeMonitor()
        for i in range(3):
            monitor._captured_queue.put(CapturedRequest(
                url=f'https://example.com/app{i}.apk',
                method='GET',
                request_headers={},
            ))
        for i in range(3):
            result = monitor.wait_for_apk(timeout=1)
            self.assertEqual(result.url, f'https://example.com/app{i}.apk')

    def test_context_manager_calls_close(self):
        monitor = ChromeMonitor()
        with patch.object(monitor, 'close') as mock_close:
            with monitor:
                pass
            mock_close.assert_called_once()


class TestWaitForApks(unittest.TestCase):
    """ChromeMonitor.wait_for_apks: 多个 APK 等待"""

    def test_returns_count_requests(self):
        monitor = ChromeMonitor()
        for i in range(3):
            monitor._captured_queue.put(CapturedRequest(
                url=f'https://example.com/app{i}.apk',
                method='GET',
                request_headers={},
            ))
        results = monitor.wait_for_apks(count=3, timeout=1)
        self.assertEqual(len(results), 3)

    def test_raises_on_insufficient_captures(self):
        monitor = ChromeMonitor()
        monitor._captured_queue.put(CapturedRequest(
            url='https://example.com/app.apk',
            method='GET',
            request_headers={},
        ))
        with self.assertRaises(ChromeMonitorError) as ctx:
            monitor.wait_for_apks(count=3, timeout=0.1)
        self.assertIn('仅捕获到', str(ctx.exception))

    def test_returns_empty_for_count_zero(self):
        monitor = ChromeMonitor()
        results = monitor.wait_for_apks(count=0, timeout=0.1)
        self.assertEqual(len(results), 0)

    def test_respects_timeout(self):
        monitor = ChromeMonitor()
        with self.assertRaises(ChromeMonitorError):
            monitor.wait_for_apks(count=2, timeout=0.1)


class TestApkDownloaderHeaders(unittest.TestCase):
    """ApkDownloader.download: headers 参数"""

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_download_accepts_headers_param(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(_make_fake_apk_bytes(4))
        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            result = downloader.download(
                'https://example.com/app.apk',
                headers={'Cookie': 'session=abc'},
            )
            self.assertTrue(result.exists())

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_headers_passed_to_request(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(_make_fake_apk_bytes(4))
        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            downloader.download(
                'https://example.com/app.apk',
                headers={'Cookie': 'session=abc', 'Authorization': 'Bearer xyz'},
            )
        args, kwargs = mock_urlopen.call_args
        req = args[0]
        self.assertEqual(req.headers.get('Cookie'), 'session=abc')
        self.assertEqual(req.headers.get('Authorization'), 'Bearer xyz')

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_cookie_header_forwarded(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(_make_fake_apk_bytes(4))
        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            downloader.download(
                'https://example.com/app.apk',
                headers={'Cookie': 'session=abc; token=xyz'},
            )
        args, _ = mock_urlopen.call_args
        req = args[0]
        self.assertIn('session=abc', req.headers.get('Cookie', ''))

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_authorization_header_forwarded(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(_make_fake_apk_bytes(4))
        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            downloader.download(
                'https://example.com/app.apk',
                headers={'Authorization': 'Bearer secret123'},
            )
        args, _ = mock_urlopen.call_args
        req = args[0]
        self.assertIn('Bearer', req.headers.get('Authorization', ''))

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_none_headers_backward_compat(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(_make_fake_apk_bytes(4))
        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            result = downloader.download('https://example.com/app.apk', headers=None)
            self.assertTrue(result.exists())

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_custom_user_agent_overrides_default(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(_make_fake_apk_bytes(4))
        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            downloader.download(
                'https://example.com/app.apk',
                headers={'User-Agent': 'Mozilla/5.0'},
            )
        args, _ = mock_urlopen.call_args
        req = args[0]
        ua = req.headers.get('User-agent') or req.headers.get('User-Agent')
        self.assertEqual(ua, 'Mozilla/5.0')


class TestPipelineMonitorIntegration(unittest.TestCase):
    """capture_pipeline --monitor 参数集成测试"""

    def test_monitor_arg_recognized(self):
        from apk_dynamic_tool.capture_pipeline import main
        argv = ['prog', '--monitor', '--monitor-port', '9222']
        with patch.object(sys, 'argv', argv):
            with patch('apk_dynamic_tool.capture_pipeline.HAS_UI2', True):
                with patch.object(ChromeMonitor, 'start') as mock_start:
                    mock_start.side_effect = ChromeMonitorError('test')
                    with patch('apk_dynamic_tool.capture_pipeline.ADBHelper') as mock_adb_cls:
                        mock_adb = MagicMock()
                        mock_adb.check_device.return_value = False
                        mock_adb_cls.return_value = mock_adb
                        with self.assertLogs(level='ERROR'):
                            main()

    def test_monitor_and_apk_mutually_exclusive(self):
        from apk_dynamic_tool.capture_pipeline import main
        argv = ['prog', '-a', 'local.apk', '--monitor']
        with patch.object(sys, 'argv', argv):
            with patch('apk_dynamic_tool.capture_pipeline.HAS_UI2', True):
                with self.assertLogs(level='ERROR') as logs:
                    main()
                self.assertTrue(any('不可同时使用' in m for m in logs.output))

    def test_monitor_and_url_mutually_exclusive(self):
        from apk_dynamic_tool.capture_pipeline import main
        argv = ['prog', '--url', 'https://x.com/a.apk', '--monitor']
        with patch.object(sys, 'argv', argv):
            with patch('apk_dynamic_tool.capture_pipeline.HAS_UI2', True):
                with self.assertLogs(level='ERROR') as logs:
                    main()
                self.assertTrue(any('不可同时使用' in m for m in logs.output))


class TestBatchAnalyzeMonitorIntegration(unittest.TestCase):
    """batch_analyze --monitor 参数集成测试"""

    @classmethod
    def setUpClass(cls):
        cls._old_path = list(sys.path)
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'main'))
        import batch_analyze
        cls.batch_analyze = batch_analyze

    @classmethod
    def tearDownClass(cls):
        sys.path[:] = cls._old_path

    def test_monitor_arg_recognized(self):
        with patch.object(ChromeMonitor, 'start') as mock_start:
            mock_start.side_effect = ChromeMonitorError('test')
            with patch.object(self.batch_analyze, 'APK_INPUT_DIR', Path('/tmp/fake')):
                with patch.object(self.batch_analyze, 'MAIN_SCRIPT', Path('/fake/main.py')):
                    with patch.object(self.batch_analyze, 'PROJECT_DIR', Path('/fake')):
                        with patch.object(self.batch_analyze.subprocess, 'run') as mock_run:
                            mock_run.return_value = MagicMock(returncode=0)
                            with patch.object(self.batch_analyze.time, 'sleep'):
                                sys_argv = ['batch_analyze', '--monitor']
                                with patch.object(sys, 'argv', sys_argv):
                                    with self.assertLogs(level='ERROR'):
                                        self.batch_analyze.main()

    def test_monitor_port_custom_value(self):
        argv = ['batch_analyze', '--monitor', '--monitor-port', '8444']
        with patch.object(sys, 'argv', argv):
            with patch.object(ChromeMonitor, 'start') as mock_start:
                mock_start.side_effect = ChromeMonitorError('test')
                with patch.object(self.batch_analyze, 'APK_INPUT_DIR', Path('/tmp/fake')):
                    with patch.object(self.batch_analyze, 'MAIN_SCRIPT', Path('/fake/main.py')):
                        with patch.object(self.batch_analyze, 'PROJECT_DIR', Path('/fake')):
                            with patch.object(self.batch_analyze.subprocess, 'run') as mock_run:
                                mock_run.return_value = MagicMock(returncode=0)
                                with patch.object(self.batch_analyze.time, 'sleep'):
                                    with self.assertLogs(level='ERROR'):
                                        self.batch_analyze.main()

    def test_monitor_and_url_mutually_exclusive(self):
        argv = ['batch_analyze', '--monitor', '--url', 'https://x.com/a.apk']
        with patch.object(sys, 'argv', argv):
            with self.assertLogs(level='ERROR') as logs:
                self.batch_analyze.main()
            self.assertTrue(any('不可同时使用' in m for m in logs.output))


if __name__ == '__main__':
    unittest.main()
