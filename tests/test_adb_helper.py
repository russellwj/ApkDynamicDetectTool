#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ADBHelper 单元测试 - 用 mock subprocess 验证ADB命令封装与输出解析"""

import unittest
from unittest import mock

from apk_dynamic_tool.adb_helper import ADBHelper


def _adb_result(stdout='', returncode=0, stderr=''):
    """构造一个假 subprocess.CompletedProcess"""
    obj = mock.MagicMock()
    obj.returncode = returncode
    obj.stdout = stdout
    obj.stderr = stderr
    return obj


class TestRunAdb(unittest.TestCase):
    """run_adb 命令组装与异常处理"""

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_includes_device_serial_when_specified(self, mock_run):
        mock_run.return_value = _adb_result('List of devices attached\n', 0)
        adb = ADBHelper(device_id='serial-XYZ')
        adb.run_adb(['devices'])
        args, kwargs = mock_run.call_args
        cmd = args[0]
        self.assertEqual(cmd[0], 'adb')
        self.assertEqual(cmd[1:3], ['-s', 'serial-XYZ'])

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_no_serial_omits_s_flag(self, mock_run):
        mock_run.return_value = _adb_result('', 0)
        adb = ADBHelper()
        adb.run_adb(['shell', 'getprop'])
        args, _ = mock_run.call_args
        cmd = args[0]
        self.assertEqual(cmd, ['adb', 'shell', 'getprop'])

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_timeout_returns_minus_one(self, mock_run):
        import subprocess as sp
        mock_run.side_effect = sp.TimeoutExpired(cmd='adb', timeout=1)
        adb = ADBHelper()
        ret, out, err = adb.run_adb(['shell', 'ls'], timeout=1)
        self.assertEqual(ret, -1)
        self.assertEqual(out, '')
        self.assertIn('Timeout', err)

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_generic_exception_returns_minus_one(self, mock_run):
        mock_run.side_effect = FileNotFoundError('no adb')
        adb = ADBHelper()
        ret, out, err = adb.run_adb(['devices'])
        self.assertEqual(ret, -1)
        self.assertIn('no adb', err)


class TestCheckDevice(unittest.TestCase):
    """check_device: 解析 adb devices 输出"""

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_single_device_auto_assigned(self, mock_run):
        mock_run.return_value = _adb_result(
            'List of devices attached\nabc123\tdevice\n', 0)
        adb = ADBHelper()
        self.assertTrue(adb.check_device())
        self.assertEqual(adb.device_id, 'abc123')

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_no_device_returns_false(self, mock_run):
        mock_run.return_value = _adb_result('List of devices attached\n', 0)
        adb = ADBHelper()
        self.assertFalse(adb.check_device())
        self.assertIsNone(adb.device_id)

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_multiple_devices_requires_serial(self, mock_run):
        mock_run.return_value = _adb_result(
            'List of devices attached\nabc\tdevice\ndef\tdevice\n', 0)
        adb = ADBHelper()
        self.assertFalse(adb.check_device())  # 多设备,未指定-s

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_adb_command_failure_returns_false(self, mock_run):
        mock_run.return_value = _adb_result('', returncode=1, stderr='daemon error')
        adb = ADBHelper()
        self.assertFalse(adb.check_device())


class TestGetScreenSize(unittest.TestCase):
    """get_screen_size: 解析 wm size 输出, 缓存"""

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_parse_physical_size(self, mock_run):
        mock_run.return_value = _adb_result(
            'Physical size: 1080x2400\n', 0)
        adb = ADBHelper()
        size = adb.get_screen_size()
        self.assertEqual(size, (1080, 2400))

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_fallback_default_on_failure(self, mock_run):
        mock_run.return_value = _adb_result('', returncode=1)
        adb = ADBHelper()
        size = adb.get_screen_size()
        self.assertEqual(size, (1080, 1920))

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_cached_value_skips_adb_call(self, mock_run):
        mock_run.return_value = _adb_result('Physical size: 720x1280\n', 0)
        adb = ADBHelper()
        first = adb.get_screen_size()
        # 第二次不应再调用subprocess
        mock_run.reset_mock()
        second = adb.get_screen_size()
        self.assertEqual(first, second)
        mock_run.assert_not_called()


class TestGetInstalledPackages(unittest.TestCase):
    """get_installed_packages: 解析 pm list packages 输出"""

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_parses_package_lines(self, mock_run):
        mock_run.return_value = _adb_result(
            'package:com.foo\npackage:com.bar\npackage:com.baz\n', 0)
        adb = ADBHelper()
        pkgs = adb.get_installed_packages()
        self.assertEqual(pkgs, {'com.foo', 'com.bar', 'com.baz'})

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_failure_returns_empty_set(self, mock_run):
        mock_run.return_value = _adb_result('', returncode=1)
        adb = ADBHelper()
        self.assertEqual(adb.get_installed_packages(), set())

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_ignores_blank_lines(self, mock_run):
        mock_run.return_value = _adb_result(
            '\npackage:com.foo\n\n', 0)
        adb = ADBHelper()
        self.assertEqual(adb.get_installed_packages(), {'com.foo'})


class TestDetectInstalledPackage(unittest.TestCase):
    """detect_installed_package: 差集检测真实包名(纯逻辑)"""

    def setUp(self):
        # 不实际调用adb: 通过 mock 注入 get_installed_packages 的返回
        self.adb = ADBHelper()

    def test_single_new_package_detected(self):
        before = {'com.a', 'com.b'}
        # 注入 after 集合(包含一个新包)
        with mock.patch.object(self.adb, 'get_installed_packages',
                               return_value=before | {'com.c'}):
            result = self.adb.detect_installed_package(before, '')
        self.assertEqual(result, 'com.c')

    def test_no_new_package_returns_empty(self):
        before = {'com.a'}
        with mock.patch.object(self.adb, 'get_installed_packages',
                               return_value=before):
            result = self.adb.detect_installed_package(before, '')
        self.assertEqual(result, '')

    def test_multiple_new_prefers_static_pkg(self):
        before = {'com.a'}
        after = before | {'com.gLVNOriR.x', 'com.ddtx.realpkg'}
        with mock.patch.object(self.adb, 'get_installed_packages',
                               return_value=after):
            result = self.adb.detect_installed_package(before, 'com.ddtx.realpkg')
        self.assertEqual(result, 'com.ddtx.realpkg')

    def test_multiple_new_matches_by_last_segment(self):
        # 静态包名末段与新包末段一致时选中
        before = {'com.a'}
        after = before | {'com.gLVNOriR.x', 'com.diff.lastseg'}
        with mock.patch.object(self.adb, 'get_installed_packages',
                               return_value=after):
            result = self.adb.detect_installed_package(before, 'com.static.lastseg')
        self.assertEqual(result, 'com.diff.lastseg')

    def test_multiple_new_no_match_returns_empty(self):
        before = {'com.a'}
        after = before | {'com.gLVNOriR.x', 'com.other.y'}
        with mock.patch.object(self.adb, 'get_installed_packages',
                               return_value=after):
            result = self.adb.detect_installed_package(before, 'com.unrelated.z')
        self.assertEqual(result, '')


class TestGetLauncherActivity(unittest.TestCase):
    """get_launcher_activity: 解析 cmd package resolve-activity 输出"""

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_absolute_activity_path(self, mock_run):
        mock_run.return_value = _adb_result(
            'priority=0 preferredOrder=0\ncom.example.app/com.example.app.MainActivity\n', 0)
        adb = ADBHelper()
        activity = adb.get_launcher_activity('com.example.app')
        self.assertEqual(activity, 'com.example.app.MainActivity')

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_relative_activity_path_expanded(self, mock_run):
        # --brief 输出 .MainAct.X 相对路径形式 → 应补全包名
        mock_run.return_value = _adb_result(
            'com.example.app/.activities.MainAct\n', 0)
        adb = ADBHelper()
        activity = adb.get_launcher_activity('com.example.app')
        self.assertEqual(activity, 'com.example.app.activities.MainAct')

    @mock.patch('apk_dynamic_tool.adb_helper.subprocess.run')
    def test_failure_returns_empty(self, mock_run):
        mock_run.return_value = _adb_result('', returncode=1)
        adb = ADBHelper()
        self.assertEqual(adb.get_launcher_activity('com.x'), '')


if __name__ == '__main__':
    unittest.main()
