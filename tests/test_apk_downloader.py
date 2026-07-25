#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""apk_downloader 单元测试 - URL下载APK并验证"""

import sys
import unittest
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from apk_dynamic_tool.apk_downloader import (
    ApkDownloader,
    ApkDownloadError,
    APK_MAGIC,
)


def _make_fake_apk_bytes(size_kb: int = 4) -> bytes:
    """构造最小有效的APK(ZIP)魔数字节流"""
    return APK_MAGIC + b'\x00' * (size_kb * 1024 - 4)


class _FakeResponse:
    """模拟 urllib.request.urlopen 返回的响应对象"""

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


class TestUrlValidation(unittest.TestCase):
    """ApkDownloader._validate_url: URL格式校验"""

    def test_https_url_valid(self):
        self.assertTrue(ApkDownloader._validate_url('https://example.com/app.apk'))

    def test_http_url_valid(self):
        self.assertTrue(ApkDownloader._validate_url('http://example.com/app.apk'))

    def test_ftp_url_invalid(self):
        self.assertFalse(ApkDownloader._validate_url('ftp://example.com/app.apk'))

    def test_empty_url_invalid(self):
        self.assertFalse(ApkDownloader._validate_url(''))

    def test_none_url_invalid(self):
        self.assertFalse(ApkDownloader._validate_url(None))

    def test_non_string_invalid(self):
        self.assertFalse(ApkDownloader._validate_url(123))


class TestInferFilename(unittest.TestCase):
    """ApkDownloader._infer_filename: 从URL推断文件名"""

    def test_url_with_apk_filename(self):
        name = ApkDownloader._infer_filename('https://example.com/downloads/myapp.apk')
        self.assertEqual(name, 'myapp.apk')

    def test_url_with_query_params(self):
        name = ApkDownloader._infer_filename('https://example.com/app.apk?token=abc&exp=123')
        self.assertEqual(name, 'app.apk')

    def test_url_with_fragment(self):
        name = ApkDownloader._infer_filename('https://example.com/app.apk#section')
        self.assertEqual(name, 'app.apk')

    def test_url_without_filename_uses_timestamp(self):
        name = ApkDownloader._infer_filename('https://example.com/')
        self.assertTrue(name.startswith('apk_'))
        self.assertIn('_', name)

    def test_url_with_path_only(self):
        name = ApkDownloader._infer_filename('https://example.com/path/to/')
        self.assertTrue(name.startswith('apk_'))


class TestValidateApk(unittest.TestCase):
    """ApkDownloader._validate_apk: APK魔数验证"""

    def test_valid_apk_magic(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as f:
            f.write(APK_MAGIC + b'\x00' * 100)
            f.flush()
            path = Path(f.name)
        try:
            self.assertTrue(ApkDownloader._validate_apk(path))
        finally:
            path.unlink()

    def test_invalid_magic(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as f:
            f.write(b'XXXX' + b'\x00' * 100)
            f.flush()
            path = Path(f.name)
        try:
            self.assertFalse(ApkDownloader._validate_apk(path))
        finally:
            path.unlink()

    def test_empty_file(self):
        with tempfile.NamedTemporaryFile(delete=False, suffix='.apk') as f:
            f.flush()
            path = Path(f.name)
        try:
            self.assertFalse(ApkDownloader._validate_apk(path))
        finally:
            path.unlink()

    def test_nonexistent_file(self):
        self.assertFalse(ApkDownloader._validate_apk(Path('no_such_file.apk')))


class TestDownloadSuccess(unittest.TestCase):
    """ApkDownloader.download: 成功下载场景"""

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_download_writes_file_and_returns_path(self, mock_urlopen):
        apk_data = _make_fake_apk_bytes(8)
        mock_urlopen.return_value = _FakeResponse(apk_data)

        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            result = downloader.download('https://example.com/test.apk')

            self.assertIsInstance(result, Path)
            self.assertTrue(result.exists())
            self.assertEqual(result.name, 'test.apk')
            self.assertEqual(result.read_bytes(), apk_data)

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_download_appends_apk_extension_if_missing(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(_make_fake_apk_bytes(4))

        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            result = downloader.download('https://example.com/myapp')

            self.assertTrue(result.name.endswith('.apk'))

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_download_creates_dir_if_not_exists(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(_make_fake_apk_bytes(2))

        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / 'sub' / 'dir'
            downloader = ApkDownloader(download_dir=str(dest))
            result = downloader.download('https://example.com/app.apk')

            self.assertTrue(dest.exists())
            self.assertTrue(result.exists())

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_download_uses_custom_filename(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(_make_fake_apk_bytes(4))

        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            result = downloader.download(
                'https://example.com/whatever', filename='custom.apk'
            )
            self.assertEqual(result.name, 'custom.apk')

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_download_progress_callback_invoked(self, mock_urlopen):
        apk_data = _make_fake_apk_bytes(16)
        mock_urlopen.return_value = _FakeResponse(apk_data)

        progress_calls = []

        def callback(downloaded, total):
            progress_calls.append((downloaded, total))

        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(
                download_dir=tmp,
                progress_callback=callback,
            )
            downloader.download('https://example.com/app.apk')

        self.assertGreater(len(progress_calls), 0)
        self.assertEqual(progress_calls[0][1], len(apk_data))
        self.assertEqual(progress_calls[-1][0], len(apk_data))

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_download_sets_user_agent_header(self, mock_urlopen):
        mock_urlopen.return_value = _FakeResponse(_make_fake_apk_bytes(2))

        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            downloader.download('https://example.com/app.apk')

        args, kwargs = mock_urlopen.call_args
        req = args[0]
        # urllib normalizes header keys to "User-agent"
        ua = req.headers.get('User-agent') or req.headers.get('User-Agent')
        self.assertIsNotNone(ua)
        self.assertIn('ApkDynamicDetectTool', ua)


class TestDownloadFailures(unittest.TestCase):
    """ApkDownloader.download: 失败场景"""

    def test_invalid_url_raises_error(self):
        downloader = ApkDownloader(download_dir=tempfile.gettempdir())
        with self.assertRaises(ApkDownloadError):
            downloader.download('not_a_url')

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_http_error_raises_download_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.HTTPError(
            'https://example.com/404', 404, 'Not Found', {}, None
        )

        downloader = ApkDownloader(download_dir=tempfile.gettempdir())
        with self.assertRaises(ApkDownloadError) as ctx:
            downloader.download('https://example.com/missing.apk')
        self.assertIn('404', str(ctx.exception))

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_url_error_raises_download_error(self, mock_urlopen):
        import urllib.error
        mock_urlopen.side_effect = urllib.error.URLError('connection refused')

        downloader = ApkDownloader(download_dir=tempfile.gettempdir())
        with self.assertRaises(ApkDownloadError) as ctx:
            downloader.download('https://example.com/app.apk')
        self.assertIn('connection refused', str(ctx.exception))

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_incomplete_download_raises_error(self, mock_urlopen):
        response = _FakeResponse(_make_fake_apk_bytes(4))
        response.headers['Content-Length'] = '99999'
        mock_urlopen.return_value = response

        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            with self.assertRaises(ApkDownloadError) as ctx:
                downloader.download('https://example.com/app.apk')
            self.assertIn('不完整', str(ctx.exception))

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_download_cleans_partial_file_on_error(self, mock_urlopen):
        mock_urlopen.side_effect = RuntimeError('network crash')

        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            with self.assertRaises(ApkDownloadError):
                downloader.download('https://example.com/app.apk')
            partial = Path(tmp) / 'app.apk'
            self.assertFalse(partial.exists())


class TestDownloadBatch(unittest.TestCase):
    """ApkDownloader.download_batch: 批量下载"""

    @patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen')
    def test_batch_mixed_success_and_failure(self, mock_urlopen):
        import urllib.error
        apk_data = _make_fake_apk_bytes(4)

        def side_effect(req, timeout=None):
            url = req.full_url
            if 'fail' in url:
                raise urllib.error.HTTPError(url, 500, 'Server Error', {}, None)
            return _FakeResponse(apk_data)

        mock_urlopen.side_effect = side_effect

        with tempfile.TemporaryDirectory() as tmp:
            downloader = ApkDownloader(download_dir=tmp)
            results = downloader.download_batch([
                'https://example.com/ok1.apk',
                'https://example.com/fail.apk',
                'https://example.com/ok2.apk',
            ])

        self.assertEqual(len(results), 3)
        self.assertTrue(results[0][0])
        self.assertFalse(results[1][0])
        self.assertTrue(results[2][0])


class TestCapturePipelineUrlIntegration(unittest.TestCase):
    """capture_pipeline --url 参数集成测试(参数解析层面)"""

    def test_url_arg_triggers_download_then_checks_device(self):
        from apk_dynamic_tool.capture_pipeline import main

        argv = ['prog', '--url', 'https://example.com/app.apk']
        with patch.object(sys, 'argv', argv):
            with patch('apk_dynamic_tool.capture_pipeline.HAS_UI2', True):
                with patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen') as mock_u:
                    mock_u.return_value = _FakeResponse(_make_fake_apk_bytes(4))
                    with patch('apk_dynamic_tool.capture_pipeline.ADBHelper') as mock_adb_cls:
                        mock_adb = MagicMock()
                        mock_adb.check_device.return_value = False
                        mock_adb_cls.return_value = mock_adb
                        main()
        mock_u.assert_called_once()

    def test_url_and_apk_mutually_exclusive(self):
        from apk_dynamic_tool.capture_pipeline import main

        argv = ['prog', '-a', 'local.apk', '--url', 'https://x.com/a.apk']
        with patch.object(sys, 'argv', argv):
            with patch('apk_dynamic_tool.capture_pipeline.HAS_UI2', True):
                with self.assertLogs(level='ERROR') as logs:
                    main()
                self.assertTrue(any('不可同时使用' in m for m in logs.output))


class TestBatchAnalyzeUrlIntegration(unittest.TestCase):
    """batch_analyze --url 参数集成测试"""

    @classmethod
    def setUpClass(cls):
        cls._old_path = list(sys.path)
        sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'main'))
        import batch_analyze
        cls.batch_analyze = batch_analyze

    @classmethod
    def tearDownClass(cls):
        sys.path[:] = cls._old_path

    def test_url_arg_downloads_before_scan(self):
        apk_data = _make_fake_apk_bytes(4)

        with tempfile.TemporaryDirectory() as tmp:
            input_dir = Path(tmp) / 'apk_input'
            input_dir.mkdir()

            with patch('apk_dynamic_tool.apk_downloader.urllib.request.urlopen') as mock_urlopen:
                mock_urlopen.return_value = _FakeResponse(apk_data)

                with patch.object(self.batch_analyze, 'APK_INPUT_DIR', input_dir):
                    with patch.object(self.batch_analyze, 'MAIN_SCRIPT', Path('/fake/main.py')):
                        with patch.object(self.batch_analyze, 'PROJECT_DIR', Path(tmp)):
                            with patch.object(self.batch_analyze.subprocess, 'run') as mock_run:
                                mock_run.return_value = MagicMock(returncode=0)
                                with patch.object(self.batch_analyze.time, 'sleep'):
                                    sys_argv = [
                                        'batch_analyze',
                                        '--url', 'https://example.com/test.apk',
                                        '--max-depth', '0',
                                    ]
                                    with patch.object(sys, 'argv', sys_argv):
                                        self.batch_analyze.main()

            apk_files = list(input_dir.glob('*.apk'))
            self.assertEqual(len(apk_files), 1)
            self.assertEqual(apk_files[0].name, 'test.apk')


if __name__ == '__main__':
    unittest.main()
