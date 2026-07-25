#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""APKAnalyzer 单元测试 - 覆盖混淆检测/候选择优/Activity选择/真实APK端到端"""

import unittest
from unittest import mock

from apk_dynamic_tool.apk_analyzer import APKAnalyzer

from tests._fixtures import APK_INPUT_DIR


class TestIsObfuscatedPackage(unittest.TestCase):
    """_is_obfuscated_package: 纯函数, 区分正常/混淆包名"""

    def test_normal_package_not_obfuscated(self):
        self.assertFalse(APKAnalyzer._is_obfuscated_package('com.example.app'))
        self.assertFalse(APKAnalyzer._is_obfuscated_package('org.foo.bar.baz'))
        self.assertFalse(APKAnalyzer._is_obfuscated_package('cn.mycompany.product'))

    def test_uppercase_in_segment_is_obfuscated(self):
        # 段名中出现大写字母 → 混淆
        self.assertTrue(APKAnalyzer._is_obfuscated_package('com.gLVNOriR.WdmKWTgvibRnrKTnFDk'))
        self.assertTrue(APKAnalyzer._is_obfuscated_package('com.X.y'))

    def test_underscore_with_digits_is_obfuscated(self):
        # 段名短 + 下划线 + 数字 → 随机字符
        self.assertTrue(APKAnalyzer._is_obfuscated_package('v3ejfn497vo_'))
        self.assertTrue(APKAnalyzer._is_obfuscated_package('com.foo.bar_1'))

    def test_consecutive_consonants_is_obfuscated(self):
        # 5+连续辅音字母 → 随机字符特征
        self.assertTrue(APKAnalyzer._is_obfuscated_package('com.bcdfgh.xxx'))

    def test_empty_package(self):
        self.assertFalse(APKAnalyzer._is_obfuscated_package(''))
        self.assertFalse(APKAnalyzer._is_obfuscated_package(None))  # type: ignore


class TestSelectBestCandidate(unittest.TestCase):
    """_select_best_candidate: 按置信度从三路候选择优"""

    def _candidates(self, andro='', aapt='', raw=''):
        return {
            'androguard': {'package': andro, 'activity': ''},
            'aapt': {'package': aapt, 'activity': ''},
            'raw_manifest': {'package': raw, 'activity': ''},
        }

    def test_multiple_methods_agree_on_clean_package(self):
        cands = self._candidates(andro='com.foo.bar', aapt='com.foo.bar', raw='com.foo.bar')
        info = APKAnalyzer._select_best_candidate(cands)
        self.assertEqual(info['package'], 'com.foo.bar')
        self.assertIn('多方法一致', info['source'])
        self.assertEqual(info['all_candidates'].count('com.foo.bar'), 3)

    def test_single_clean_candidate_picks_androguard_first(self):
        cands = self._candidates(andro='com.a.b', aapt='', raw='')
        info = APKAnalyzer._select_best_candidate(cands)
        self.assertEqual(info['package'], 'com.a.b')
        self.assertEqual(info['source'], 'androguard')

    def test_obfuscated_only_prefers_raw_manifest(self):
        cands = self._candidates(
            andro='com.gLVNOriR.WdmK',
            aapt='com.gLVNOriR.WdmK',
            raw='com.ddtx.realpkg'
        )
        info = APKAnalyzer._select_best_candidate(cands)
        # 全部混淆时, raw_manifest 优先(对混淆最鲁棒)
        self.assertEqual(info['package'], 'com.ddtx.realpkg')
        self.assertIn('raw_manifest', info['source'])

    def test_raw_empty_falls_back_to_any_obfuscated(self):
        cands = self._candidates(andro='com.gLVNOriR.X', aapt='', raw='')
        info = APKAnalyzer._select_best_candidate(cands)
        self.assertEqual(info['package'], 'com.gLVNOriR.X')
        self.assertIn('混淆兜底', info['source'])

    def test_all_empty_returns_empty_info(self):
        cands = self._candidates()
        info = APKAnalyzer._select_best_candidate(cands)
        self.assertEqual(info['package'], '')
        self.assertEqual(info['source'], '')
        self.assertEqual(info['all_candidates'], [])


class TestSelectActivity(unittest.TestCase):
    """_select_activity: 优先级 androguard > aapt > raw_manifest"""

    def test_priority_order(self):
        cands = {
            'androguard': {'package': 'p', 'activity': 'A1'},
            'aapt': {'package': 'p', 'activity': 'A2'},
            'raw_manifest': {'package': 'p', 'activity': 'A3'},
        }
        self.assertEqual(APKAnalyzer._select_activity(cands), 'A1')

        cands['androguard']['activity'] = ''
        self.assertEqual(APKAnalyzer._select_activity(cands), 'A2')

        cands['aapt']['activity'] = ''
        self.assertEqual(APKAnalyzer._select_activity(cands), 'A3')

    def test_all_empty_returns_empty(self):
        cands = {k: {'package': '', 'activity': ''} for k in ['androguard', 'aapt', 'raw_manifest']}
        self.assertEqual(APKAnalyzer._select_activity(cands), '')

    def test_string_none_treated_as_empty(self):
        # 历史bug: androguard可能返回字符串'None'
        cands = {'androguard': {'package': 'p', 'activity': 'None'},
                 'aapt': {'package': 'p', 'activity': 'A2'},
                 'raw_manifest': {'package': 'p', 'activity': ''}}
        self.assertEqual(APKAnalyzer._select_activity(cands), 'A2')


class TestExtractFromRawManifest(unittest.TestCase):
    """_extract_from_raw_manifest: 对非APK文件优雅返回空"""

    def test_non_zip_file_returns_empty(self):
        # 一个普通的文本文件, 不是zip
        import tempfile
        with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as f:
            f.write(b'not a zip file')
            path = f.name
        try:
            info = APKAnalyzer._extract_from_raw_manifest(path)
            self.assertEqual(info, {'package': '', 'activity': ''})
        finally:
            import os as _os
            _os.remove(path)

    def test_zip_without_manifest_returns_empty(self):
        import tempfile, zipfile
        with tempfile.NamedTemporaryFile(suffix='.apk', delete=False) as f:
            path = f.name
        try:
            with zipfile.ZipFile(path, 'w') as zf:
                zf.writestr('other.txt', 'hello')
            info = APKAnalyzer._extract_from_raw_manifest(path)
            self.assertEqual(info, {'package': '', 'activity': ''})
        finally:
            import os as _os
            _os.remove(path)


class TestGetPackageInfoE2E(unittest.TestCase):
    """get_package_info 端到端: 用 apk_input/demo.apk(若存在)验证三路候选融合"""

    def setUp(self):
        self.demo_apk = APK_INPUT_DIR / 'demo.apk'
        if not self.demo_apk.exists():
            self.skipTest('apk_input/demo.apk 不存在, 跳过端到端测试')

    def test_demo_apk_returns_valid_package(self):
        info = APKAnalyzer.get_package_info(str(self.demo_apk))
        self.assertTrue(info.get('package'), '应能解析出包名')
        self.assertIn('source', info)
        # 至少有一种来源标注
        self.assertTrue(info['source'])
        # all_candidates应包含解析到的包名
        self.assertIn(info['package'], info.get('all_candidates', []))

    def test_nonexistent_apk_returns_empty(self):
        info = APKAnalyzer.get_package_info('no_such_file_xyz.apk')
        self.assertEqual(info, {})


class TestFindAapt(unittest.TestCase):
    """_find_aapt: 环境相关, 但至少应能优雅返回(字符串, 可能为空)"""

    def test_returns_string(self):
        result = APKAnalyzer._find_aapt()
        self.assertIsInstance(result, str)


if __name__ == '__main__':
    unittest.main()
