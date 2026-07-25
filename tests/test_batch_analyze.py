#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""batch_analyze 单元测试 - find_apk_files / format_duration / run_analysis"""

import sys
import unittest
import tempfile
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).parent.parent / 'main'))
import batch_analyze


class TestFormatDuration(unittest.TestCase):
    """format_duration: 时长格式化"""

    def test_seconds_only(self):
        self.assertEqual(batch_analyze.format_duration(45), '45秒')
        self.assertEqual(batch_analyze.format_duration(0), '0秒')

    def test_minutes_and_seconds(self):
        self.assertEqual(batch_analyze.format_duration(90), '1分30秒')
        self.assertEqual(batch_analyze.format_duration(125), '2分5秒')
        self.assertEqual(batch_analyze.format_duration(3600), '60分0秒')

    def test_float_seconds_truncated(self):
        # .0f 格式使用标准四舍五入: 45.4 → 45, 45.6 → 46
        self.assertEqual(batch_analyze.format_duration(45.0), '45秒')
        self.assertEqual(batch_analyze.format_duration(45.4), '45秒')


class TestFindApkFiles(unittest.TestCase):
    """find_apk_files: 扫描目录按文件名排序返回APK"""

    def test_finds_apk_files_sorted(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / 'b.apk').write_bytes(b'')
            (d / 'a.apk').write_bytes(b'')
            (d / 'c.txt').write_bytes(b'')  # 非APK忽略
            (d / 'sub_dir').mkdir()

            result = batch_analyze.find_apk_files(d)
            names = [p.name for p in result]
            self.assertEqual(names, ['a.apk', 'b.apk'])

    def test_skip_list_excludes_named_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / 'a.apk').write_bytes(b'')
            (d / 'b.apk').write_bytes(b'')
            (d / 'c.apk').write_bytes(b'')

            result = batch_analyze.find_apk_files(d, skip_list=['b.apk'])
            names = [p.name for p in result]
            self.assertEqual(names, ['a.apk', 'c.apk'])

    def test_nonexistent_dir_returns_empty(self):
        result = batch_analyze.find_apk_files(Path('no_such_dir_xyz'))
        self.assertEqual(result, [])

    def test_empty_dir_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(batch_analyze.find_apk_files(Path(tmp)), [])

    def test_case_insensitive_extension(self):
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / 'Upper.APK').write_bytes(b'')
            result = batch_analyze.find_apk_files(d)
            self.assertEqual(len(result), 1)


class TestRunAnalysis(unittest.TestCase):
    """run_analysis: 委托给subprocess调用主脚本"""

    @mock.patch('batch_analyze.subprocess.run')
    @mock.patch('batch_analyze.time.time', return_value=1000.0)
    def test_success_returns_true_with_duration(self, mock_time, mock_run):
        mock_run.return_value = mock.MagicMock(returncode=0)

        success, duration = batch_analyze.run_analysis(
            Path('/fake/app.apk'), extra_args=['--max-depth', '5'])

        self.assertTrue(success)
        # duration = time.time() - start_time, 两边都被mock成1000.0 → 0.0
        self.assertIsInstance(duration, float)
        self.assertEqual(duration, 0.0)
        # 命令应包含解释器 + 主脚本 + -a + apk路径 + 额外参数
        args, kwargs = mock_run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], batch_analyze.sys.executable)
        self.assertIn('apk_capture_final.py', cmd[1])
        self.assertEqual(cmd[2:4], ['-a', str(Path('/fake/app.apk'))])
        self.assertIn('--max-depth', cmd)
        self.assertIn('5', cmd)
        # capture_output=False(直接控制台输出)
        self.assertFalse(kwargs.get('capture_output', True))

    @mock.patch('batch_analyze.subprocess.run')
    def test_nonzero_returncode_returns_false(self, mock_run):
        mock_run.return_value = mock.MagicMock(returncode=1)
        success, _ = batch_analyze.run_analysis(Path('/fake/app.apk'))
        self.assertFalse(success)

    @mock.patch('batch_analyze.subprocess.run')
    def test_timeout_returns_false(self, mock_run):
        import subprocess as sp
        mock_run.side_effect = sp.TimeoutExpired(cmd='python', timeout=600)
        success, _ = batch_analyze.run_analysis(Path('/fake/app.apk'))
        self.assertFalse(success)

    @mock.patch('batch_analyze.subprocess.run')
    def test_generic_exception_returns_false(self, mock_run):
        mock_run.side_effect = OSError('disk full')
        success, _ = batch_analyze.run_analysis(Path('/fake/app.apk'))
        self.assertFalse(success)


if __name__ == '__main__':
    unittest.main()
