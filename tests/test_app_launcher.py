#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AppLauncher / AppTraverser 单元测试 - 用FakeDevice验证交互逻辑"""

import unittest
from pathlib import Path
from unittest import mock

from apk_dynamic_tool.adb_helper import ADBHelper
from apk_dynamic_tool.app_launcher import AppLauncher
from apk_dynamic_tool.app_traverser import AppTraverser

from tests._fixtures import FakeDevice, make_adb_with_responses


# 全局加速: launch_app/traverse_page/handle_permission_dialogs内部有time.sleep,
# 测试中patch成no-op以避免每个用例等待数秒
@mock.patch('apk_dynamic_tool.app_launcher.time.sleep', lambda s: None)
@mock.patch('apk_dynamic_tool.app_traverser.time.sleep', lambda s: None)
@mock.patch('apk_dynamic_tool.dialog_handlers.time.sleep', lambda s: None)
class TestAppLauncher(unittest.TestCase):
    """AppLauncher: am start与monkey兜底"""

    def test_launch_success_with_activity(self):
        # 'am start' 子串匹配实际命令(shell am start -n pkg/activity ...)
        adb = make_adb_with_responses({
            'am start': (0, 'Starting: Intent', ''),
        }, default_response=(0, '', ''))
        launcher = AppLauncher(adb)
        result = launcher.launch_app('com.foo', 'com.foo.Main', device=None)
        self.assertTrue(result)

    def test_launch_failure_falls_back_to_monkey(self):
        # am start失败 → monkey兜底成功
        responses = {
            'am start': (1, '', 'Error: not found'),
            'monkey -p': (0, 'Events injected', ''),
        }
        adb = make_adb_with_responses(responses, default_response=(0, '', ''))
        launcher = AppLauncher(adb)
        result = launcher.launch_app('com.foo', 'com.foo.Main', device=None)
        self.assertTrue(result)  # monkey兜底成功

    def test_both_methods_fail_returns_false(self):
        responses = {
            'am start': (1, '', 'Error'),
            'monkey -p': (1, '', 'Error'),
        }
        adb = make_adb_with_responses(responses, default_response=(0, '', ''))
        launcher = AppLauncher(adb)
        result = launcher.launch_app('com.foo', 'com.foo.Main', device=None)
        self.assertFalse(result)

    def test_stop_app_calls_force_stop(self):
        captured = {}

        def fake_run(args, timeout=60):
            captured['args'] = args
            return (0, '', '')

        adb = ADBHelper(device_id='fake-001')
        adb.run_adb = fake_run
        launcher = AppLauncher(adb)
        launcher.stop_app('com.foo')
        self.assertEqual(captured['args'],
                         ['shell', 'am', 'force-stop', 'com.foo'])

    def test_launch_with_stdout_error_triggers_fallback(self):
        # am start返回0但stdout含'Error' → fallback
        responses = {
            'am start': (0, 'Error: Activity not found', ''),
            'monkey -p': (0, 'OK', ''),
        }
        adb = make_adb_with_responses(responses, default_response=(0, '', ''))
        launcher = AppLauncher(adb)
        result = launcher.launch_app('com.foo', 'com.foo.Main', device=None)
        self.assertTrue(result)


@mock.patch('apk_dynamic_tool.app_traverser.time.sleep', lambda s: None)
@mock.patch('apk_dynamic_tool.dialog_handlers.time.sleep', lambda s: None)
class TestAppTraverserPureLogic(unittest.TestCase):
    """AppTraverser: 纯逻辑方法(不依赖真实device)"""

    def setUp(self):
        self.device = FakeDevice()
        self.output_dir = Path('.') / '_traverse_test_tmp'
        self.output_dir.mkdir(exist_ok=True)
        self.traverser = AppTraverser(self.device, 'com.foo.app', self.output_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.output_dir, ignore_errors=True)

    def test_screenshots_dir_created(self):
        self.assertTrue((self.output_dir / 'screenshots').exists())

    def test_should_skip_element_with_skip_keyword(self):
        elem = {'text': '登录', 'description': ''}
        self.assertTrue(self.traverser.should_skip_element(elem))

        elem = {'text': '', 'description': '购买VIP'}
        self.assertTrue(self.traverser.should_skip_element(elem))

    def test_should_not_skip_normal_element(self):
        elem = {'text': '首页', 'description': 'home'}
        self.assertFalse(self.traverser.should_skip_element(elem))

    def test_should_skip_matches_description_keyword(self):
        # 关键字在description中也应触发跳过
        elem = {'text': '', 'description': '购买VIP'}
        self.assertTrue(self.traverser.should_skip_element(elem))

    def test_get_element_signature_unique_per_combination(self):
        e1 = {'resource_id': 'id1', 'class': 'Btn', 'text': 'Click me'}
        e2 = {'resource_id': 'id2', 'class': 'Btn', 'text': 'Click me'}
        e3 = {'resource_id': 'id1', 'class': 'Btn', 'text': 'Different'}
        sig1 = self.traverser.get_element_signature(e1)
        sig2 = self.traverser.get_element_signature(e2)
        sig3 = self.traverser.get_element_signature(e3)
        self.assertNotEqual(sig1, sig2)
        self.assertNotEqual(sig1, sig3)

    def test_get_current_app_info_returns_dict(self):
        self.device.app_current_value = {'package': 'com.foo', 'activity': 'MainAct'}
        info = self.traverser.get_current_app_info()
        self.assertEqual(info, {'package': 'com.foo', 'activity': 'MainAct'})

    def test_get_current_app_info_handles_failure(self):
        # 让app_current抛异常, 应返回空dict
        self.device.app_current = mock.MagicMock(side_effect=Exception('boom'))
        info = self.traverser.get_current_app_info()
        self.assertEqual(info, {'package': '', 'activity': ''})

    def test_save_log_writes_json(self):
        # 模拟一些遍历状态
        self.traverser.visited_activities.add('com.foo/Main')
        self.traverser.clicked_elements.add('id1_Btn_Click')
        self.traverser.traverse_log.append({
            'timestamp': '2024-01-01T00:00:00',
            'depth': 0, 'action': 'click',
            'element': 'button', 'activity': 'com.foo/Main'
        })
        self.traverser.save_log()
        log_path = self.output_dir / 'traverse_log.json'
        self.assertTrue(log_path.exists())
        import json
        data = json.loads(log_path.read_text(encoding='utf-8'))
        self.assertEqual(data['package_name'], 'com.foo.app')
        self.assertIn('com.foo/Main', data['visited_activities'])
        self.assertEqual(data['clicked_elements_count'], 1)
        self.assertEqual(len(data['traverse_log']), 1)


@mock.patch('apk_dynamic_tool.app_traverser.time.sleep', lambda s: None)
@mock.patch('apk_dynamic_tool.dialog_handlers.time.sleep', lambda s: None)
class TestAppTraverserHandleDialogs(unittest.TestCase):
    """handle_permission_dialogs: 验证风险/权限弹窗点击"""

    def setUp(self):
        self.device = FakeDevice()
        self.output_dir = Path('.') / '_traverse_dialog_tmp'
        self.output_dir.mkdir(exist_ok=True)
        self.traverser = AppTraverser(self.device, 'com.foo', self.output_dir)

    def tearDown(self):
        import shutil
        shutil.rmtree(self.output_dir, ignore_errors=True)

    def test_risk_warning_dialog_clicks_continue(self):
        # 注入一个"继续使用"按钮
        elem = self.device.set_element(text='继续使用', clickable=True)
        self.traverser.handle_permission_dialogs()
        self.assertTrue(elem.clicked)

    def test_permission_dialog_clicks_allow(self):
        # handle_permission_dialogs对权限弹窗使用 textContains= 查找
        elem = self.device.set_element(textContains='允许', clickable=True)
        self.traverser.handle_permission_dialogs()
        self.assertTrue(elem.clicked)

    def test_no_dialog_does_not_throw(self):
        # 无任何弹窗, 应正常返回不报错
        self.traverser.handle_permission_dialogs()


if __name__ == '__main__':
    unittest.main()
