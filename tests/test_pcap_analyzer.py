#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""PCAPAnalyzer 单元测试 - Scapy合成包验证 DNS/HTTP/TLS SNI/IP/TCP/UDP 解析"""

import unittest
import tempfile
from pathlib import Path
from unittest import mock

# scapy导入会有警告, 在Windows下无libpcap, 仅离线rdpcap需要
import warnings
warnings.filterwarnings('ignore')

from scapy.all import IP, UDP, TCP, DNS, DNSQR, DNSRR, Raw, Ether, wrpcap

from apk_dynamic_tool.pcap_analyzer import PCAPAnalyzer, IPInfoProvider

from tests._fixtures import build_tls_client_hello_with_sni


def _dns_query_pkt(domain, src='1.1.1.1', dst='8.8.8.8', sport=12345, dport=53):
    """DNS标准查询"""
    return (IP(src=src, dst=dst) /
            UDP(sport=sport, dport=dport) /
            DNS(id=1, qr=0, qd=DNSQR(qname=domain.encode())))


def _dns_response_pkt(domain, ip_list=None, cnames=None,
                      src='8.8.8.8', dst='1.1.1.1', sport=53, dport=12345):
    """DNS响应: A记录用IP字符串, CNAME记录用bytes域名(FQDN末尾点)"""
    an = []
    if ip_list:
        for ip in ip_list:
            an.append(DNSRR(rrname=domain.encode() + b'.', type='A',
                            rdata=ip, ttl=60))
    if cnames:
        for cn in cnames:
            an.append(DNSRR(rrname=domain.encode() + b'.', type='CNAME',
                            rdata=cn.encode() + b'.', ttl=60))
    return (IP(src=src, dst=dst) /
            UDP(sport=sport, dport=dport) /
            DNS(id=1, qr=1, qd=DNSQR(qname=domain.encode()), an=an))


def _http_request_pkt(method, host, path, src='1.1.1.1', dst='2.2.2.2',
                      sport=12345, dport=80):
    payload = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode()
    return (IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(load=payload))


def _https_pkt(hostname, src='1.1.1.1', dst='2.2.2.2',
               sport=12345, dport=443):
    payload = build_tls_client_hello_with_sni(hostname)
    return (IP(src=src, dst=dst) / TCP(sport=sport, dport=dport) / Raw(load=payload))


class TestExtractDnsAnswer(unittest.TestCase):
    """_extract_dns_answer: 按rdata Python类型区分A/CNAME/TXT"""

    class FakeAnswer:
        def __init__(self, rdata):
            self.rdata = rdata

    def test_a_record_returns_ip(self):
        kind, value = PCAPAnalyzer._extract_dns_answer(self.FakeAnswer('1.2.3.4'))
        self.assertEqual(kind, 'ip')
        self.assertEqual(value, '1.2.3.4')

    def test_aaaa_record_returns_ip(self):
        kind, value = PCAPAnalyzer._extract_dns_answer(
            self.FakeAnswer('2001:db8::1'))
        self.assertEqual(kind, 'ip')

    def test_cname_record_decodes_and_strips_dot(self):
        kind, value = PCAPAnalyzer._extract_dns_answer(
            self.FakeAnswer(b'alias.example.com.'))
        self.assertEqual(kind, 'cname')
        self.assertEqual(value, 'alias.example.com')

    def test_cname_without_trailing_dot(self):
        kind, value = PCAPAnalyzer._extract_dns_answer(
            self.FakeAnswer(b'alias.example.com'))
        self.assertEqual(kind, 'cname')
        self.assertEqual(value, 'alias.example.com')

    def test_txt_record_skipped(self):
        # rdata为list → 非IP非域名, 跳过避免污染
        self.assertEqual(
            PCAPAnalyzer._extract_dns_answer(self.FakeAnswer([b'txt', b'data'])),
            ('', ''))

    def test_bytes_literal_string_blocked(self):
        # 防御性清洗: 字符串"b'xxx'"应被识别为脏数据
        kind, value = PCAPAnalyzer._extract_dns_answer(self.FakeAnswer("b'xxx'"))
        self.assertEqual((kind, value), ('', ''))

    def test_no_rdata_attr_returns_empty(self):
        # 没有rdata属性的对象
        self.assertEqual(PCAPAnalyzer._extract_dns_answer(object()), ('', ''))


class TestExtractSni(unittest.TestCase):
    """_extract_sni: 从TLS ClientHello字节流提取SNI"""

    def test_valid_sni(self):
        payload = build_tls_client_hello_with_sni('example.com')
        self.assertEqual(PCAPAnalyzer._extract_sni(payload), 'example.com')

    def test_multi_subdomain(self):
        payload = build_tls_client_hello_with_sni('api.service.example.org')
        self.assertEqual(PCAPAnalyzer._extract_sni(payload), 'api.service.example.org')

    def test_non_handshake_returns_empty(self):
        # content_type不是0x16
        self.assertEqual(PCAPAnalyzer._extract_sni(b'\x17\x03\x01\x00\x00'), '')

    def test_not_clienthello_returns_empty(self):
        # content_type=0x16但handshake type不是0x01
        payload = b'\x16\x03\x01\x00\x05\x02\x00\x00\x03\x00'
        self.assertEqual(PCAPAnalyzer._extract_sni(payload), '')

    def test_to_short_payload(self):
        self.assertEqual(PCAPAnalyzer._extract_sni(b'\x16'), '')

    def test_no_sni_extension_returns_empty(self):
        # 构造一个无SNI扩展的ClientHello(扩展block为空)
        # 复用build_tls但hostname=''; 实际我们的build总会加SNI,
        # 这里直接手写一个无SNI的最小ClientHello
        # extensions_len = 0
        comp_block = b'\x01\x00'  # 1 compression method: null
        cipher_block = b'\x00\x02\x00\x2f'  # 1 cipher suite
        hello_body = (b'\x03\x03' + b'\x00' * 32 + b'\x00' +  # version + random + session_id_len=0
                      cipher_block + comp_block + b'\x00\x00')  # extensions_len=0
        handshake = b'\x01' + len(hello_body).to_bytes(3, 'big') + hello_body
        tls_record = b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake
        self.assertEqual(PCAPAnalyzer._extract_sni(tls_record), '')


class TestPktTimeStr(unittest.TestCase):
    """_pkt_time_str: 时间戳转HH:MM:SS (实例方法, 需通过实例调用)"""

    def setUp(self):
        self.analyzer = PCAPAnalyzer('dummy.pcap')

    def test_zero_or_negative_returns_empty(self):
        self.assertEqual(self.analyzer._pkt_time_str(0), '')
        self.assertEqual(self.analyzer._pkt_time_str(-1), '')

    def test_valid_timestamp(self):
        # 固定时间戳: 2024-01-01 12:00:00 UTC
        # datetime.fromtimestamp使用本地时区, 仅验证格式
        s = self.analyzer._pkt_time_str(1704110400.0)
        self.assertRegex(s, r'^\d{2}:\d{2}:\d{2}$')


class TestAnalyzeDns(unittest.TestCase):
    """_analyze_dns: DNS查询与响应解析"""

    def test_dns_query_records_domain(self):
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_dns(_dns_query_pkt('example.com'), pkt_time=1000.0)
        entry = a.dns_queries['example.com']
        self.assertEqual(entry['first_seen'], 1000.0)
        self.assertEqual(entry['last_seen'], 1000.0)
        self.assertEqual(set(entry['ips']), set())
        self.assertEqual(set(entry['cnames']), set())

    def test_dns_response_records_ips(self):
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_dns(_dns_response_pkt('example.com', ip_list=['1.2.3.4', '5.6.7.8']),
                       pkt_time=1000.0)
        self.assertEqual(a.dns_queries['example.com']['ips'], {'1.2.3.4', '5.6.7.8'})
        # IP反向索引: ip_connections[1.2.3.4]['domains']含example.com
        self.assertIn('example.com', a.ip_connections['1.2.3.4']['domains'])

    def test_dns_response_records_cnames_separately(self):
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_dns(_dns_response_pkt('www.example.com',
                                          ip_list=['1.2.3.4'],
                                          cnames=['alias.example.com']),
                       pkt_time=1000.0)
        # CNAME存入cnames, 不污染ips
        self.assertEqual(a.dns_queries['www.example.com']['ips'], {'1.2.3.4'})
        self.assertEqual(a.dns_queries['www.example.com']['cnames'],
                         {'alias.example.com'})

    def test_dns_response_updates_timestamps(self):
        a = PCAPAnalyzer('dummy.pcap')
        # 先查询再响应, 时间戳应被合并
        a._analyze_dns(_dns_query_pkt('foo.com'), pkt_time=900.0)
        a._analyze_dns(_dns_response_pkt('foo.com', ip_list=['1.1.1.1']),
                       pkt_time=1000.0)
        entry = a.dns_queries['foo.com']
        self.assertEqual(entry['first_seen'], 900.0)
        self.assertEqual(entry['last_seen'], 1000.0)


class TestAnalyzeHttp(unittest.TestCase):
    """_analyze_http: 明文HTTP完整URL提取"""

    def test_get_request_with_host_and_path(self):
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_http(_http_request_pkt('GET', 'example.com', '/api/v1?x=1'),
                        pkt_time=1000.0)
        self.assertEqual(len(a.http_urls), 1)
        entry = next(iter(a.http_urls.values()))
        self.assertEqual(entry['method'], 'GET')
        self.assertEqual(entry['host'], 'example.com')
        self.assertEqual(entry['path'], '/api/v1?x=1')
        self.assertEqual(entry['url'], 'http://example.com/api/v1?x=1')

    def test_post_request(self):
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_http(_http_request_pkt('POST', 'api.foo.com', '/submit'),
                        pkt_time=1000.0)
        entry = next(iter(a.http_urls.values()))
        self.assertEqual(entry['method'], 'POST')
        self.assertEqual(entry['url'], 'http://api.foo.com/submit')

    def test_absolute_url_in_request_line(self):
        # 有些代理请求行带完整URL
        payload = b'GET http://example.com/abs HTTP/1.1\r\nHost: example.com\r\n\r\n'
        pkt = (IP(src='1.1.1.1', dst='2.2.2.2') /
               TCP(sport=12345, dport=80) / Raw(load=payload))
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_http(pkt, pkt_time=1000.0)
        entry = next(iter(a.http_urls.values()))
        self.assertEqual(entry['url'], 'http://example.com/abs')

    def test_dedup_by_method_url(self):
        a = PCAPAnalyzer('dummy.pcap')
        pkt = _http_request_pkt('GET', 'example.com', '/path')
        a._analyze_http(pkt, pkt_time=1000.0)
        a._analyze_http(pkt, pkt_time=1100.0)
        # 相同URL只记一条, count=2
        self.assertEqual(len(a.http_urls), 1)
        entry = next(iter(a.http_urls.values()))
        self.assertEqual(entry['count'], 2)
        self.assertEqual(entry['first_seen'], 1000.0)
        self.assertEqual(entry['last_seen'], 1100.0)

    def test_no_host_skipped(self):
        payload = b'GET /path HTTP/1.1\r\n\r\n'
        pkt = (IP(src='1.1.1.1', dst='2.2.2.2') /
               TCP(sport=12345, dport=80) / Raw(load=payload))
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_http(pkt, pkt_time=1000.0)
        self.assertEqual(len(a.http_urls), 0)

    def test_non_http_skipped(self):
        payload = b'NOT-HTTP random bytes here'
        pkt = (IP(src='1.1.1.1', dst='2.2.2.2') /
               TCP(sport=12345, dport=80) / Raw(load=payload))
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_http(pkt, pkt_time=1000.0)
        self.assertEqual(len(a.http_urls), 0)


class TestAnalyzeTlsSni(unittest.TestCase):
    """_analyze_tls_sni: 从HTTPS ClientHello提取SNI"""

    def test_extracts_sni(self):
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_tls_sni(_https_pkt('example.com'), pkt_time=1000.0)
        self.assertIn('example.com', a.tls_snis)
        self.assertEqual(a.tls_snis['example.com']['count'], 1)

    def test_non_tls_skipped(self):
        pkt = (IP(src='1.1.1.1', dst='2.2.2.2') /
               TCP(sport=12345, dport=443) / Raw(load=b'\x17\x03\x01\x00\x00'))
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_tls_sni(pkt, pkt_time=1000.0)
        self.assertEqual(len(a.tls_snis), 0)

    def test_count_increments(self):
        a = PCAPAnalyzer('dummy.pcap')
        pkt = _https_pkt('api.foo.com')
        a._analyze_tls_sni(pkt, pkt_time=1000.0)
        a._analyze_tls_sni(pkt, pkt_time=1100.0)
        self.assertEqual(a.tls_snis['api.foo.com']['count'], 2)
        self.assertEqual(a.tls_snis['api.foo.com']['first_seen'], 1000.0)
        self.assertEqual(a.tls_snis['api.foo.com']['last_seen'], 1100.0)


class TestAnalyzeIpTcpUdp(unittest.TestCase):
    """_analyze_ip/_analyze_tcp/_analyze_udp: 流量与连接统计"""

    def test_ip_records_packet_count_and_bytes(self):
        pkt = IP(src='1.1.1.1', dst='2.2.2.2') / TCP(sport=1000, dport=80) / Raw(load=b'x' * 100)
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_ip(pkt, pkt_time=1000.0)
        # 源和目的都应被记录
        self.assertEqual(a.ip_connections['1.1.1.1']['packet_count'], 1)
        self.assertEqual(a.ip_connections['2.2.2.2']['packet_count'], 1)
        # 字节数 = 整个IP包长度
        self.assertGreater(a.ip_connections['1.1.1.1']['bytes'], 0)
        self.assertEqual(a.ip_connections['1.1.1.1']['first_seen'], 1000.0)

    def test_tcp_records_stream_and_port(self):
        pkt = IP(src='1.1.1.1', dst='2.2.2.2') / TCP(sport=1000, dport=80) / Raw(load=b'GET')
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_tcp(pkt)
        self.assertEqual(len(a.tcp_streams), 1)
        stream = a.tcp_streams[0]
        self.assertEqual(stream['src_ip'], '1.1.1.1')
        self.assertEqual(stream['src_port'], 1000)
        self.assertEqual(stream['dst_ip'], '2.2.2.2')
        self.assertEqual(stream['dst_port'], 80)
        self.assertEqual(stream['protocol'], 'TCP')
        # 端口记录到目的IP下
        self.assertIn(80, a.ip_connections['2.2.2.2']['ports'])

    def test_tcp_dedup_same_stream(self):
        pkt = IP(src='1.1.1.1', dst='2.2.2.2') / TCP(sport=1000, dport=80)
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_tcp(pkt)
        a._analyze_tcp(pkt)  # 相同五元组
        self.assertEqual(len(a.tcp_streams), 1)

    def test_udp_records_stream(self):
        pkt = IP(src='1.1.1.1', dst='8.8.8.8') / UDP(sport=12345, dport=53)
        a = PCAPAnalyzer('dummy.pcap')
        a._analyze_udp(pkt)
        self.assertEqual(len(a.udp_streams), 1)
        self.assertEqual(a.udp_streams[0]['protocol'], 'UDP')
        self.assertIn(53, a.ip_connections['8.8.8.8']['ports'])


class TestFullAnalyzePipeline(unittest.TestCase):
    """端到端: 合成pcap → load → analyze → generate_report"""

    def _build_pcap(self, packets):
        tmp = tempfile.NamedTemporaryFile(suffix='.pcap', delete=False)
        tmp.close()
        wrpcap(tmp.name, packets)
        self.addCleanup(Path(tmp.name).unlink, missing_ok=True)
        return tmp.name

    def test_load_and_analyze_synthetic_pcap(self):
        packets = [
            _dns_query_pkt('example.com'),
            _dns_response_pkt('example.com', ip_list=['1.2.3.4']),
            _http_request_pkt('GET', 'example.com', '/index.html'),
            _https_pkt('secure.example.com'),
        ]
        pcap_path = self._build_pcap(packets)

        a = PCAPAnalyzer(pcap_path)
        self.assertTrue(a.load_pcap())
        self.assertEqual(len(a.packets), len(packets))
        a.analyze()

        # 验证各表
        self.assertIn('example.com', a.dns_queries)
        self.assertIn('1.2.3.4', a.dns_queries['example.com']['ips'])
        self.assertEqual(len(a.http_urls), 1)
        self.assertIn('secure.example.com', a.tls_snis)

    def test_generate_report_writes_json_and_html(self):
        packets = [
            _dns_response_pkt('foo.com', ip_list=['1.2.3.4']),
            _http_request_pkt('GET', 'foo.com', '/path'),
        ]
        pcap_path = self._build_pcap(packets)

        with tempfile.TemporaryDirectory() as tmp_dir:
            report_file = str(Path(tmp_dir) / 'report.json')
            a = PCAPAnalyzer(pcap_path)
            a.load_pcap()
            a.analyze()

            # mock掉IP地理位置API(避免外网依赖)
            a.ip_provider.get_ip_info = lambda ip: {  # type: ignore
                'ip': ip, 'country': 'US', 'region': 'CA',
                'city': 'MV', 'isp': 'TestISP', 'org': 'TestOrg',
                'as': 'AS123', 'cloud_provider': '', 'cloud_category': ''
            }

            report = a.generate_report(report_file)

            # JSON文件已生成
            self.assertTrue(Path(report_file).exists())
            # HTML文件也生成了(report_file.replace('.json', '.html'))
            html_file = report_file.replace('.json', '.html')
            self.assertTrue(Path(html_file).exists())

            # 报告内容验证
            self.assertEqual(report['summary']['total_packets'], 2)
            self.assertGreaterEqual(report['summary']['total_domains'], 1)
            self.assertEqual(report['summary']['total_urls'], 1)
            # 域名列表应包含foo.com且解析IP正确
            domains = [d['domain'] for d in report['domains']]
            self.assertIn('foo.com', domains)


class TestIPInfoProviderCloud(unittest.TestCase):
    """IPInfoProvider._identify_cloud_provider: 云厂商关键字匹配"""

    def setUp(self):
        self.provider = IPInfoProvider()

    def test_aliyun_match(self):
        info = {'org': 'Aliyun Computing Co., Ltd', 'isp': '', 'as': ''}
        result = self.provider._identify_cloud_provider(info)
        self.assertEqual(result['cloud_provider'], '阿里云')
        self.assertEqual(result['cloud_category'], 'aliyun')

    def test_aws_match(self):
        info = {'org': 'Amazon.com Inc.', 'isp': '', 'as': 'AS123 Amazon'}
        result = self.provider._identify_cloud_provider(info)
        self.assertEqual(result['cloud_provider'], 'AWS')
        self.assertEqual(result['cloud_category'], 'aws')

    def test_china_telecom_match(self):
        info = {'org': 'China Telecom', 'isp': '', 'as': ''}
        result = self.provider._identify_cloud_provider(info)
        self.assertEqual(result['cloud_provider'], '中国电信')
        self.assertEqual(result['cloud_category'], 'operator')

    def test_unknown_provider_returns_empty(self):
        info = {'org': 'Some Unknown ISP', 'isp': '', 'as': ''}
        result = self.provider._identify_cloud_provider(info)
        self.assertEqual(result['cloud_provider'], '')
        self.assertEqual(result['cloud_category'], '')

    def test_get_ip_info_caches_result(self):
        # 同一IP第二次查询应命中缓存(不会触发网络)
        with mock.patch('urllib.request.urlopen') as mock_open:
            # 构造假响应
            mock_resp = mock.MagicMock()
            mock_resp.read.return_value = b'{"status":"success","country":"US","regionName":"CA","city":"MV","isp":"Test","org":"Test","as":"AS1"}'
            mock_resp.__enter__.return_value = mock_resp
            mock_resp.__exit__.return_value = False
            mock_open.return_value = mock_resp

            result1 = self.provider.get_ip_info('8.8.8.8')
            result2 = self.provider.get_ip_info('8.8.8.8')
            self.assertIs(result1, result2)  # 缓存: 同一对象
            self.assertEqual(mock_open.call_count, 1)  # 只调用一次网络


if __name__ == '__main__':
    unittest.main()
