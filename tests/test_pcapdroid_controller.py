#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PCAPdroidController 单元测试 - API命令构造 / api_key读取 / pcap文件查找"""

import unittest
import tempfile
from pathlib import Path
from unittest import mock

from apk_dynamic_tool.pcapdroid_controller import PCAPdroidController
from apk_dynamic_tool.adb_helper import ADBHelper

from tests._fixtures import make_adb_with_responses


def _ctrl_with_api_key(key='testkey1234567890'):
    """构造带固定api_key的PCAPdroidController(关闭设备安全设置副作用)"""
    adb = ADBHelper(device_id='fake-001')
    adb.run_adb = lambda args, timeout=60: (0, '', '')  # disable_security_notifications打桩
    return PCAPdroidController(adb, device=None, api_key=key)


class TestRunApiCommandConstruction(unittest.TestCase):
    """_run_api: 校验Intent参数与CaptureCtrl目标组件"""

    def test_start_action_includes_extra_params(self):
        captured = {}

        def fake_run(args, timeout=60):
            captured['args'] = args
            return (0, 'Starting: Intent...', '')

        adb = ADBHelper(device_id='fake-001')
        adb.run_adb = fake_run
        ctrl = PCAPdroidController(adb, device=None, api_key='MYKEY')
        ctrl._run_api('start', {'pcap_dump_mode': 'pcap_file', 'pcap_name': 'capture_x'})

        cmd = captured['args']
        # 关键参数必须出现且顺序合理
        self.assertIn('shell', cmd)
        self.assertIn('am', cmd)
        self.assertIn('start', cmd)
        # -e action start -e api_key MYKEY
        action_idx = cmd.index('-e') + 1  # 'action'
        self.assertEqual(cmd[action_idx], 'action')
        self.assertEqual(cmd[action_idx + 1], 'start')
        # -e api_key MYKEY
        # 查找 'api_key' 字面量后的值
        api_key_idx = cmd.index('api_key')
        self.assertEqual(cmd[api_key_idx + 1], 'MYKEY')
        # -n com.emanuelef.remote_capture/.activities.CaptureCtrl
        self.assertIn('-n', cmd)
        self.assertEqual(cmd[cmd.index('-n') + 1],
                         'com.emanuelef.remote_capture/.activities.CaptureCtrl')
        # 额外参数
        self.assertIn('pcap_dump_mode', cmd)
        self.assertEqual(cmd[cmd.index('pcap_dump_mode') + 1], 'pcap_file')
        self.assertIn('pcap_name', cmd)
        self.assertEqual(cmd[cmd.index('pcap_name') + 1], 'capture_x')

    def test_stop_action_minimal_params(self):
        captured = {}

        def fake_run(args, timeout=60):
            captured['args'] = args
            return (0, '', '')

        adb = ADBHelper(device_id='fake-001')
        adb.run_adb = fake_run
        ctrl = PCAPdroidController(adb, device=None, api_key='K')
        ctrl._run_api('stop')

        cmd = captured['args']
        self.assertIn('stop', cmd)
        # 不应包含pcap_dump_mode
        self.assertNotIn('pcap_dump_mode', cmd)

    def test_extra_params_values_stringified(self):
        captured = {}

        def fake_run(args, timeout=60):
            captured['args'] = args
            return (0, '', '')

        adb = ADBHelper(device_id='fake-001')
        adb.run_adb = fake_run
        ctrl = PCAPdroidController(adb, device=None, api_key='K')
        # 数字值应转字符串
        ctrl._run_api('start', {'port': 8080})
        self.assertIn('port', captured['args'])
        self.assertEqual(captured['args'][captured['args'].index('port') + 1], '8080')


class TestReadApiKeyFromFile(unittest.TestCase):
    """_read_api_key_from_file: 多路径查找"""

    def test_reads_pcap_txt_from_cwd(self):
        # 真实场景: 在临时CWD下放一份PCAP.txt, 验证能读取
        import os
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmp)
                (Path(tmp) / 'PCAP.txt').write_text('KEYXYZ\n', encoding='utf-8')
                adb = ADBHelper(device_id='fake-001')
                adb.run_adb = lambda args, timeout=60: (0, '', '')
                ctrl = PCAPdroidController(adb, device=None, api_key=None)
                self.assertEqual(ctrl.api_key, 'KEYXYZ')
            finally:
                os.chdir(old_cwd)

    def test_no_pcap_txt_returns_empty(self):
        # 没有任何PCAP.txt(临时CWD为空, 模块同目录也没有)
        import os
        with tempfile.TemporaryDirectory() as tmp:
            old_cwd = os.getcwd()
            try:
                os.chdir(tmp)
                adb = ADBHelper(device_id='fake-001')
                adb.run_adb = lambda args, timeout=60: (0, '', '')
                ctrl = PCAPdroidController(adb, device=None, api_key=None)
                self.assertEqual(ctrl.api_key, '')
            finally:
                os.chdir(old_cwd)

    def test_explicit_api_key_takes_precedence(self):
        # 显式传入api_key时不读文件
        adb = ADBHelper(device_id='fake-001')
        adb.run_adb = lambda args, timeout=60: (0, '', '')
        ctrl = PCAPdroidController(adb, device=None, api_key='MYKEY')
        self.assertEqual(ctrl.api_key, 'MYKEY')


class TestCheckInstallation(unittest.TestCase):
    """check_installation: 查询包名是否存在"""

    def test_installed(self):
        adb = make_adb_with_responses({
            'remote_capture': (0, 'package:com.emanuelef.remote_capture', ''),
        })
        ctrl = PCAPdroidController(adb, device=None, api_key='K')
        self.assertTrue(ctrl.check_installation())

    def test_not_installed(self):
        adb = make_adb_with_responses({}, default_response=(0, '', ''))
        ctrl = PCAPdroidController(adb, device=None, api_key='K')
        self.assertFalse(ctrl.check_installation())


class TestFindLatestPcapFile(unittest.TestCase):
    """_find_latest_pcap_file: 模拟ls/stat返回, 验证查找与文件大小校验"""

    def test_finds_nonempty_pcap_file(self):
        responses = {
            # ls -t <location>
            'ls -t /sdcard/Download/PCAPdroid': (0, 'capture_20260724_120000\nother.txt\n', ''),
            # stat -c %s <path>
            'stat -c %s /sdcard/Download/PCAPdroid/capture_20260724_120000': (0, '4096\n', ''),
        }
        adb = make_adb_with_responses(responses)
        ctrl = PCAPdroidController(adb, device=None, api_key='K')
        result = ctrl._find_latest_pcap_file()
        self.assertEqual(result, '/sdcard/Download/PCAPdroid/capture_20260724_120000')

    def test_skips_empty_pcap_file(self):
        responses = {
            'ls -t /sdcard/Download/PCAPdroid': (0, 'capture_20260724_120000.pcap\n', ''),
            'stat -c %s /sdcard/Download/PCAPdroid/capture_20260724_120000.pcap': (0, '0\n', ''),
        }
        adb = make_adb_with_responses(responses)
        ctrl = PCAPdroidController(adb, device=None, api_key='K')
        result = ctrl._find_latest_pcap_file()
        self.assertIsNone(result)

    def test_all_locations_empty_returns_none(self):
        adb = make_adb_with_responses({}, default_response=(0, '', ''))
        ctrl = PCAPdroidController(adb, device=None, api_key='K')
        self.assertIsNone(ctrl._find_latest_pcap_file())


class TestCheckVpnActive(unittest.TestCase):
    """_check_vpn_active: 解析 ifconfig/ip addr 输出"""

    def test_ifconfig_with_up_running(self):
        adb = make_adb_with_responses({
            'ifconfig tun0': (0, 'tun0: flags=4163  mtu 1280\n  UP RUNNING', ''),
        })
        ctrl = PCAPdroidController(adb, device=None, api_key='K')
        self.assertTrue(ctrl._check_vpn_active())

    def test_ifconfig_without_up_running(self):
        # ifconfig 没有UP/RUNNING, ip addr也没有UP → False
        adb = make_adb_with_responses({}, default_response=(1, '', ''))
        ctrl = PCAPdroidController(adb, device=None, api_key='K')
        self.assertFalse(ctrl._check_vpn_active())

    def test_fallback_to_ip_addr(self):
        # ifconfig失败, 但ip addr返回UP
        def fake_run(args, timeout=60):
            args_str = ' '.join(args)
            if 'ifconfig' in args_str:
                return (1, '', 'no such device')
            if 'ip addr' in args_str:
                return (0, '1: tun0: <POINTOPOINT,MULTICAST,NOARP,UP> mtu 1280', '')
            return (0, '', '')

        adb = ADBHelper(device_id='fake-001')
        adb.run_adb = fake_run
        ctrl = PCAPdroidController(adb, device=None, api_key='K')
        self.assertTrue(ctrl._check_vpn_active())


class TestClearOldPcapFiles(unittest.TestCase):
    """_clear_old_pcap_files: 验证会调用rm清理.pcap与capture_前缀文件"""

    def test_calls_rm_for_pcap_files(self):
        rm_commands = []

        def fake_run(args, timeout=60):
            if 'ls' in args and '/sdcard' in args[-1]:
                return (0, 'capture_20260724_120000.pcap\nold.txt\n', '')
            if 'rm' in args:
                rm_commands.append(args[-1])
                return (0, '', '')
            return (0, '', '')

        adb = ADBHelper(device_id='fake-001')
        adb.run_adb = fake_run
        ctrl = PCAPdroidController(adb, device=None, api_key='K')
        ctrl._clear_old_pcap_files()

        # 应对每个 PCAP_LOCATIONS 中的目录都尝试清理
        # capture_xxx.pcap 被清理, old.txt 不被清理
        self.assertTrue(any('capture_20260724_120000.pcap' in c for c in rm_commands))
        self.assertFalse(any('old.txt' in c for c in rm_commands))


if __name__ == '__main__':
    unittest.main()
