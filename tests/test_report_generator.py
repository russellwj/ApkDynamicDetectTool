#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""ReportGenerator 单元测试 - 聚合/清洗/格式化纯函数"""

import unittest
from unittest import mock

from apk_dynamic_tool.report_generator import ReportGenerator


class TestIsPrivateIp(unittest.TestCase):
    """_is_private_ip: 内网IP判定"""

    def test_private_ranges(self):
        for ip in ['10.0.0.1', '10.255.255.255',
                   '172.16.0.1', '172.31.255.255',
                   '192.168.1.1', '127.0.0.1', '169.254.0.1']:
            self.assertTrue(ReportGenerator._is_private_ip(ip), f'{ip} 应为私有')

    def test_public_ips(self):
        for ip in ['8.8.8.8', '1.1.1.1', '172.32.0.1', '172.15.0.1',
                   '192.169.0.1', '11.0.0.1']:
            self.assertFalse(ReportGenerator._is_private_ip(ip), f'{ip} 应为公网')

    def test_invalid_ip_returns_false(self):
        self.assertFalse(ReportGenerator._is_private_ip('not.an.ip'))
        self.assertFalse(ReportGenerator._is_private_ip('1.2.3'))
        self.assertFalse(ReportGenerator._is_private_ip(''))


class TestIsCleanIp(unittest.TestCase):
    """_is_clean_ip: 防御性清洗 b'xxx.' 脏字符串"""

    def test_clean_ip_returns_true(self):
        self.assertTrue(ReportGenerator._is_clean_ip('1.2.3.4'))
        self.assertTrue(ReportGenerator._is_clean_ip('2001:db8::1'))

    def test_bytes_literal_string_returns_false(self):
        # 历史bug: str(bytes) → "b'xxx.'"
        self.assertFalse(ReportGenerator._is_clean_ip("b'alias.example.com.'"))
        self.assertFalse(ReportGenerator._is_clean_ip('b"another.example.com."'))

    def test_empty_returns_false(self):
        self.assertFalse(ReportGenerator._is_clean_ip(''))
        self.assertFalse(ReportGenerator._is_clean_ip(None))  # type: ignore


class TestCloudBadgeHtmlSimple(unittest.TestCase):
    """_cloud_badge_html_simple: 云厂商徽章背景色"""

    def test_huawei_red(self):
        html = ReportGenerator._cloud_badge_html_simple('华为云', 'huawei')
        self.assertIn('华为云', html)
        self.assertIn('#d32f2f', html)  # 红色
        self.assertIn('white', html)  # 白字

    def test_aliyun_yellow(self):
        html = ReportGenerator._cloud_badge_html_simple('阿里云', 'aliyun')
        self.assertIn('阿里云', html)
        self.assertIn('#f9a825', html)  # 黄色

    def test_operator_green(self):
        html = ReportGenerator._cloud_badge_html_simple('中国移动', 'operator')
        self.assertIn('#43a047', html)  # 绿色

    def test_other_gray(self):
        html = ReportGenerator._cloud_badge_html_simple('谷歌云', 'other')
        self.assertIn('#757575', html)  # 灰色

    def test_empty_provider_returns_dash(self):
        html = ReportGenerator._cloud_badge_html_simple('', '')
        self.assertIn('-', html)
        self.assertIn('#999', html)

    def test_unknown_category_defaults_gray(self):
        html = ReportGenerator._cloud_badge_html_simple('某云', 'unknown_category')
        self.assertIn('#757575', html)


class TestAggregateIpLocations(unittest.TestCase):
    """_aggregate_ip_locations: 聚合多IP的地理位置与厂商(去重)"""

    def test_dedup_locations_and_providers(self):
        ip_infos = [
            {'location': {'country': 'US', 'city': 'MV',
                          'cloud_provider': 'AWS', 'cloud_category': 'aws'}},
            {'location': {'country': 'US', 'city': 'MV',
                          'cloud_provider': 'AWS', 'cloud_category': 'aws'}},  # 重复
            {'location': {'country': 'CN', 'city': 'Hangzhou',
                          'cloud_provider': '阿里云', 'cloud_category': 'aliyun'}},
            {'location': {'country': 'N/A', 'city': 'N/A',  # N/A 应被过滤
                          'cloud_provider': '', 'cloud_category': ''}},
        ]
        locations, providers = ReportGenerator._aggregate_ip_locations(ip_infos)
        self.assertEqual(locations, ['US MV', 'CN Hangzhou'])
        self.assertEqual(providers, [('AWS', 'aws'), ('阿里云', 'aliyun')])

    def test_empty_input_returns_empty_lists(self):
        locs, provs = ReportGenerator._aggregate_ip_locations([])
        self.assertEqual(locs, [])
        self.assertEqual(provs, [])

    def test_only_city_present(self):
        # country存在但city为空 → loc_str=country
        ip_infos = [{'location': {'country': 'US', 'city': '',
                                  'cloud_provider': '', 'cloud_category': ''}}]
        locs, _ = ReportGenerator._aggregate_ip_locations(ip_infos)
        self.assertEqual(locs, ['US'])


class TestAggregateTime(unittest.TestCase):
    """_aggregate_time: 多来源时间聚合(最早/最晚)"""

    def test_picks_earliest_first_and_latest_last(self):
        dns = {'first_seen_ts': 1000.0, 'first_seen': '10:00:00', 'last_seen': '10:01:00'}
        sni = {'first_seen_ts': 1500.0, 'first_seen': '10:05:00', 'last_seen': '10:06:00'}
        http = [{'first_seen_ts': 1200.0, 'first_seen': '10:02:00', 'last_seen': '10:03:00'}]
        ts, first, last = ReportGenerator._aggregate_time(dns, sni, http)
        self.assertEqual(ts, 1000.0)  # 最早
        self.assertEqual(first, '10:00:00')  # 字符串最小
        self.assertEqual(last, '10:06:00')  # 字符串最大

    def test_missing_sources_returns_empty(self):
        ts, first, last = ReportGenerator._aggregate_time({}, {}, [])
        self.assertEqual((ts, first, last), (0, '', ''))

    def test_partial_sources_only(self):
        # 只有DNS, 没SNI/HTTP
        dns = {'first_seen_ts': 500.0, 'first_seen': '08:00:00', 'last_seen': '08:00:30'}
        ts, first, last = ReportGenerator._aggregate_time(dns, {}, [])
        self.assertEqual(ts, 500.0)
        self.assertEqual(first, '08:00:00')
        self.assertEqual(last, '08:00:30')

    def test_zero_timestamps_filtered(self):
        # 时间戳为0/缺失的应被跳过
        dns = {'first_seen_ts': 0, 'first_seen': '', 'last_seen': ''}
        sni = {'first_seen_ts': 1000.0, 'first_seen': '10:00:00', 'last_seen': '10:01:00'}
        ts, first, last = ReportGenerator._aggregate_time(dns, sni, [])
        self.assertEqual(ts, 1000.0)
        self.assertEqual(first, '10:00:00')


class TestCollectUnifiedRecords(unittest.TestCase):
    """_collect_unified_records: 以域名为粒度聚合所有通信来源"""

    def _make_traffic_info(self):
        return {
            'summary': {},
            'domains': [
                {'domain': 'foo.com', 'resolved_ips': ['1.2.3.4'],
                 'cnames': ['alias.foo.com'],
                 'first_seen': '10:00:00', 'last_seen': '10:01:00',
                 'first_seen_ts': 1000.0},
                {'domain': 'bar.com', 'resolved_ips': ['5.6.7.8'],
                 'cnames': [],
                 'first_seen': '10:05:00', 'last_seen': '10:06:00',
                 'first_seen_ts': 1500.0},
            ],
            'tls_snis': [
                {'domain': 'secure.foo.com', 'count': 3,
                 'first_seen': '10:02:00', 'last_seen': '10:03:00',
                 'first_seen_ts': 1200.0},
            ],
            'urls': [
                {'method': 'GET', 'url': 'http://foo.com/path', 'host': 'foo.com',
                 'path': '/path', 'count': 2,
                 'first_seen': '10:00:30', 'last_seen': '10:00:45',
                 'first_seen_ts': 1030.0},
            ],
            'ips': [
                {'ip': '1.2.3.4', 'domains': ['foo.com'],
                 'location': {'country': 'US', 'city': 'MV',
                              'cloud_provider': 'AWS', 'cloud_category': 'aws'}},
                {'ip': '5.6.7.8', 'domains': ['bar.com'],
                 'location': {'country': 'CN', 'city': 'Beijing',
                              'cloud_provider': '', 'cloud_category': ''}},
            ],
        }

    def test_aggregates_all_sources_by_domain(self):
        gen = ReportGenerator()
        gen.traffic_info = self._make_traffic_info()
        records = gen._collect_unified_records()

        domains = {r['domain'] for r in records}
        self.assertEqual(domains, {'foo.com', 'bar.com', 'secure.foo.com'})

        # 按first_seen_ts升序排序
        ts_list = [r['first_seen_ts'] for r in records]
        self.assertEqual(ts_list, sorted(ts_list))

    def test_foo_com_record_has_http_https_dns_info(self):
        gen = ReportGenerator()
        gen.traffic_info = self._make_traffic_info()
        records = gen._collect_unified_records()
        foo = next(r for r in records if r['domain'] == 'foo.com')

        # DNS提供IP
        self.assertEqual(foo['resolved_ips'], ['1.2.3.4'])
        # DNS提供CNAME
        self.assertEqual(foo['cnames'], ['alias.foo.com'])
        # HTTP提供URL
        self.assertEqual(len(foo['http_urls']), 1)
        self.assertEqual(foo['http_urls'][0]['method'], 'GET')
        # 协议: 有HTTP (没HTTPS因为foo.com没有TLS SNI, secure.foo.com才有)
        self.assertIn('HTTP', foo['protocols'])
        # 请求次数 = HTTP count之和 = 2
        self.assertEqual(foo['request_count'], 2)
        # 地理位置从IP连接反查
        self.assertIn('US MV', foo['locations'])
        # 厂商
        self.assertIn(('AWS', 'aws'), foo['cloud_providers'])
        # 时间: HTTP首次10:00:30, DNS首次10:00:00 → 最早10:00:00
        self.assertEqual(foo['first_seen'], '10:00:00')

    def test_https_only_domain(self):
        gen = ReportGenerator()
        gen.traffic_info = self._make_traffic_info()
        records = gen._collect_unified_records()
        secure = next(r for r in records if r['domain'] == 'secure.foo.com')

        self.assertIn('HTTPS', secure['protocols'])
        # 没有HTTP URL → URL列说明路径加密
        self.assertEqual(secure['http_urls'], [])
        # 请求次数 = SNI count = 3
        self.assertEqual(secure['request_count'], 3)
        # 方法应包含'TLS SNI'
        self.assertIn('TLS SNI', secure['methods'])

    def test_dns_only_domain(self):
        gen = ReportGenerator()
        gen.traffic_info = self._make_traffic_info()
        records = gen._collect_unified_records()
        bar = next(r for r in records if r['domain'] == 'bar.com')

        # 没HTTP没HTTPS → 协议为空, 方法为DNS查询
        self.assertEqual(bar['protocols'], [])
        self.assertIn('DNS查询', bar['methods'])

    def test_empty_traffic_info(self):
        gen = ReportGenerator()
        gen.traffic_info = {}
        self.assertEqual(gen._collect_unified_records(), [])

    def test_dirty_ip_in_resolved_ips_filtered(self):
        # 历史JSON残留 b'xxx.' 脏字符串应被过滤
        gen = ReportGenerator()
        gen.traffic_info = {
            'domains': [
                {'domain': 'dirty.com',
                 'resolved_ips': ["b'alias.dirty.com.'", '1.2.3.4'],
                 'cnames': [],
                 'first_seen': '', 'last_seen': '', 'first_seen_ts': 0},
            ],
            'tls_snis': [], 'urls': [], 'ips': [],
        }
        records = gen._collect_unified_records()
        dirty = next(r for r in records if r['domain'] == 'dirty.com')
        # 脏数据被过滤, 只剩正常IP
        self.assertEqual(dirty['resolved_ips'], ['1.2.3.4'])


class TestFormatUrlCell(unittest.TestCase):
    """_format_url_cell: HTTP展示完整URL, HTTPS标注路径加密"""

    def test_http_urls_listed(self):
        rec = {
            'http_urls': [
                {'method': 'GET', 'url': 'http://foo.com/a'},
                {'method': 'POST', 'url': 'http://foo.com/b'},
            ],
            'protocols': ['HTTP'],
        }
        html = ReportGenerator._format_url_cell(rec)
        self.assertIn('GET', html)
        self.assertIn('http://foo.com/a', html)
        self.assertIn('POST', html)
        self.assertIn('http://foo.com/b', html)

    def test_http_urls_truncated_with_count(self):
        rec = {
            'http_urls': [{'method': 'GET', 'url': f'http://foo.com/p{i}'} for i in range(5)],
            'protocols': ['HTTP'],
        }
        html = ReportGenerator._format_url_cell(rec)
        # 前3条 + "+2 个URL"提示
        self.assertIn('http://foo.com/p0', html)
        self.assertIn('http://foo.com/p2', html)
        self.assertIn('+2', html)

    def test_https_only_shows_encrypted_note(self):
        rec = {
            'http_urls': [],
            'protocols': ['HTTPS'],
            'domain': 'secure.example.com',
        }
        html = ReportGenerator._format_url_cell(rec)
        self.assertIn('https://secure.example.com/', html)
        self.assertIn('路径加密', html)

    def test_no_data_returns_dash(self):
        rec = {'http_urls': [], 'protocols': []}
        html = ReportGenerator._format_url_cell(rec)
        self.assertEqual(html.strip(), '-')


class TestGenerateReportEndToEnd(unittest.TestCase):
    """端到端: 用一份traffic_info生成HTML报告"""

    def _default_apk_info(self):
        """模拟load_apk_info后的最小完整apk_info(所有_build_apk_section需要的键)"""
        return {
            'file_name': 'demo.apk', 'file_size': 1024, 'file_size_mb': 0.001,
            'md5': 'a' * 32, 'sha256': 'b' * 64,
            'package_name': 'com.demo.app', 'version_name': '1.0',
            'version_code': '1', 'main_activity': 'com.demo.app.MainActivity',
            'permissions': ['android.permission.INTERNET'],
            'signing_info': [],
            'min_sdk': '21', 'target_sdk': '33',
            'app_name': 'DemoApp',
            'analyze_time': '2024-01-01 00:00:00',
        }

    def test_generate_html_report_writes_file(self):
        import tempfile, os
        gen = ReportGenerator()
        gen.apk_info = self._default_apk_info()
        # 最小traffic_info
        gen.traffic_info = {
            'summary': {'total_packets': 10, 'total_urls': 1,
                        'total_tls_snis': 1, 'total_domains': 1, 'total_ips': 1},
            'domains': [{'domain': 'foo.com', 'resolved_ips': ['1.2.3.4'],
                         'cnames': [], 'first_seen': '', 'last_seen': '',
                         'first_seen_ts': 0}],
            'tls_snis': [{'domain': 'secure.foo.com', 'count': 1,
                          'first_seen': '', 'last_seen': '', 'first_seen_ts': 0}],
            'urls': [],
            'ips': [],
        }
        # 源码内部用print输出emoji(✅), 在Windows GBK控制台会UnicodeEncodeError, 屏蔽之
        with mock.patch('builtins.print'):
            with tempfile.TemporaryDirectory() as tmp:
                out_file = os.path.join(tmp, 'report.html')
                gen.generate_html_report(out_file)
                self.assertTrue(os.path.exists(out_file))
                content = open(out_file, encoding='utf-8').read()
                self.assertIn('APK安全分析报告', content)
                self.assertIn('foo.com', content)
                self.assertIn('secure.foo.com', content)


if __name__ == '__main__':
    unittest.main()
