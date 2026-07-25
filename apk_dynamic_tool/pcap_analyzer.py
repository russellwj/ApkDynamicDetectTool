#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAP文件解析和报告生成工具
提取域名、IP、端口、地理位置、厂商等信息
"""

import json
import subprocess
import argparse
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Set, Tuple
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

try:
    from scapy.all import rdpcap, DNS, DNSQR, IP, TCP, UDP, conf
    conf.verb = 0  # 关闭scapy的警告输出
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    logger.error("❌ scapy未安装，请运行: pip install scapy")


class IPInfoProvider:
    """IP信息查询提供者"""
    
    # 云厂商识别规则（基于org/isp/as字段匹配）
    CLOUD_PROVIDER_RULES = [
        # (匹配关键字列表, 中文显示名, 背景色类别)
        (['huawei', '华为', 'hcicloud'], '华为云', 'huawei'),
        (['aliyun', 'aliyuncs', 'alibaba', '阿里', '阿里云', '.alibaba'], '阿里云', 'aliyun'),
        (['tencent', '腾讯', 'tencent cloud'], '腾讯云', 'tencent'),
        (['amazon', 'aws', 'amazon.com'], 'AWS', 'aws'),
        # 国内移动运营商
        (['china mobile', '中国移动', 'cmcc'], '中国移动', 'operator'),
        (['china unicom', '中国联通', 'unicom', 'cnc'], '中国联通', 'operator'),
        (['china telecom', '中国电信', 'telecom', 'ctc', 'chinatelecom'], '中国电信', 'operator'),
        # 其他常见云
        (['microsoft', 'azure', 'microsoft azure'], '微软云', 'other'),
        (['google', 'google cloud', 'google llc'], '谷歌云', 'other'),
        (['oracle', 'oracle cloud'], '甲骨文云', 'other'),
        (['baidu', 'bce', '百度'], '百度云', 'other'),
        (['jdcloud', '京东云', 'jd'], '京东云', 'other'),
        (['ucloud'], 'UCloud', 'other'),
        (['kingsoft', 'ks3', '金山'], '金山云', 'other'),
    ]
    
    def __init__(self):
        self.cache = {}
    
    def _identify_cloud_provider(self, info: Dict) -> Dict:
        """根据IP的org/isp/as字段识别云厂商"""
        text = ' '.join([
            str(info.get('org', '')),
            str(info.get('isp', '')),
            str(info.get('as', ''))
        ]).lower()
        
        for keywords, cn_name, category in self.CLOUD_PROVIDER_RULES:
            for kw in keywords:
                if kw.lower() in text:
                    info['cloud_provider'] = cn_name
                    info['cloud_category'] = category  # huawei/aliyun/tencent/aws/operator/other
                    return info
        
        info['cloud_provider'] = ''
        info['cloud_category'] = ''
        return info
    
    def get_ip_info(self, ip: str) -> Dict:
        """
        获取IP的地理位置和厂商信息
        使用免费的IP查询API
        """
        if ip in self.cache:
            return self.cache[ip]
        
        info = {
            'ip': ip,
            'country': 'N/A',
            'region': 'N/A',
            'city': 'N/A',
            'isp': 'N/A',
            'org': 'N/A',
            'as': 'N/A'
        }
        
        try:
            # 使用ip-api.com免费API（每分钟45次请求限制）
            import urllib.request
            import json
            
            url = f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as"
            
            req = urllib.request.Request(url)
            req.add_header('User-Agent', 'Mozilla/5.0')
            
            with urllib.request.urlopen(req, timeout=5) as response:
                data = json.loads(response.read().decode())
                
                if data.get('status') == 'success':
                    info.update({
                        'country': data.get('country', 'N/A'),
                        'region': data.get('regionName', 'N/A'),
                        'city': data.get('city', 'N/A'),
                        'isp': data.get('isp', 'N/A'),
                        'org': data.get('org', 'N/A'),
                        'as': data.get('as', 'N/A')
                    })
        except Exception as e:
            logger.debug(f"查询IP信息失败 {ip}: {e}")
        
        # 识别云厂商
        info = self._identify_cloud_provider(info)
        
        self.cache[ip] = info
        return info


class PCAPAnalyzer:
    """PCAP文件分析器"""
    
    def __init__(self, pcap_file: str):
        self.pcap_file = pcap_file
        self.packets = None
        
        # 分析结果
        # 域名 -> {ips: Set, cnames: Set, first_seen: float(时间戳), last_seen: float}
        # cnames: DNS响应中的CNAME别名(已decode、去FQDN末尾点)，与ips分开存放避免污染
        self.dns_queries: Dict[str, Dict] = defaultdict(lambda: {
            'ips': set(),
            'cnames': set(),
            'first_seen': None,
            'last_seen': None
        })
        self.ip_connections: Dict[str, Dict] = defaultdict(lambda: {
            'domains': set(),
            'ports': set(),
            'packet_count': 0,
            'bytes': 0,
            'first_seen': None,
            'last_seen': None
        })
        self.tcp_streams: List[Dict] = []
        self.udp_streams: List[Dict] = []
        # HTTP完整URL (明文HTTP流量可见完整URL，含路径与参数)
        # key = "METHOD URL"，去重并记录次数与时间
        self.http_urls: Dict[str, Dict] = defaultdict(lambda: {
            'method': '', 'url': '', 'host': '', 'path': '',
            'count': 0, 'first_seen': None, 'last_seen': None
        })
        # TLS SNI服务器名 (HTTPS通信的域名，路径加密不可见)
        self.tls_snis: Dict[str, Dict] = defaultdict(lambda: {
            'first_seen': None, 'last_seen': None, 'count': 0
        })
        self.pcap_start_time: float = 0  # PCAP起始时间（用于相对时间计算）
        self.pcap_end_time: float = 0
        
        # IP信息提供者
        self.ip_provider = IPInfoProvider()
    
    def load_pcap(self) -> bool:
        """加载PCAP文件"""
        if not HAS_SCAPY:
            logger.error("❌ 需要scapy库支持")
            return False
        
        try:
            logger.info(f"📂 加载PCAP文件: {self.pcap_file}")
            self.packets = rdpcap(self.pcap_file)
            logger.info(f"✅ 加载成功，共 {len(self.packets)} 个数据包")
            return True
        except Exception as e:
            logger.error(f"❌ 加载PCAP文件失败: {e}")
            return False
    
    def analyze(self):
        """分析PCAP文件"""
        if not self.packets:
            logger.error("❌ 未加载数据包")
            return
        
        logger.info("🔍 开始分析数据包...")
        
        # 记录PCAP时间范围
        if len(self.packets) > 0:
            self.pcap_start_time = float(self.packets[0].time)
            self.pcap_end_time = float(self.packets[-1].time)
        
        # 统计信息
        dns_count = 0
        tcp_count = 0
        udp_count = 0
        
        for packet in self.packets:
            try:
                pkt_time = float(packet.time)
                
                # 分析DNS查询
                if packet.haslayer(DNS):
                    self._analyze_dns(packet, pkt_time)
                    dns_count += 1
                
                # 分析IP层
                if packet.haslayer(IP):
                    self._analyze_ip(packet, pkt_time)
                
                # 分析TCP/UDP
                if packet.haslayer(TCP):
                    self._analyze_tcp(packet)
                    # 提取HTTP完整URL和TLS SNI（不丢URL信息的关键）
                    self._analyze_http(packet, pkt_time)
                    self._analyze_tls_sni(packet, pkt_time)
                    tcp_count += 1
                elif packet.haslayer(UDP):
                    self._analyze_udp(packet)
                    udp_count += 1

            except Exception as e:
                logger.debug(f"分析数据包失败: {e}")
                continue

        logger.info(f"✅ 分析完成:")
        logger.info(f"   DNS查询: {dns_count}")
        logger.info(f"   TCP数据包: {tcp_count}")
        logger.info(f"   UDP数据包: {udp_count}")
        logger.info(f"   HTTP完整URL: {len(self.http_urls)}")
        logger.info(f"   TLS SNI域名: {len(self.tls_snis)}")
    
    def _pkt_time_str(self, pkt_time: float) -> str:
        """将数据包时间戳转为可读字符串"""
        if pkt_time <= 0:
            return ''
        try:
            dt = datetime.fromtimestamp(pkt_time)
            return dt.strftime('%H:%M:%S')
        except Exception:
            return ''
    
    @staticmethod
    def _extract_dns_answer(answer) -> tuple:
        """从DNS应答记录提取类型与清洗后的值

        scapy对DNS记录rdata的表示因记录类型而异：
        - A/AAAA记录(type=1/28): rdata为IP字符串(如 '1.2.3.4')
        - CNAME/NS/PTR记录(type=5/2/12): rdata为bytes域名(如 b'alias.example.com.'，带FQDN末尾点)
        - TXT记录(type=16): rdata为list[bytes](如 [b'text...'])，非IP非域名
        若对bytes/list直接str()会得到 "b'xxx.'" 或 "[b'xxx']" 脏字符串污染报告，
        因此需按Python类型区分处理。

        Returns:
            (kind, value): kind为'ip'(A/AAAA)或'cname'(域名类); 其他记录返回('', '')
        """
        if not hasattr(answer, 'rdata'):
            return '', ''
        rdata = answer.rdata
        # 域名类记录: rdata为bytes，decode并去掉FQDN末尾点
        if isinstance(rdata, bytes):
            return 'cname', rdata.decode('utf-8', errors='ignore').rstrip('.')
        # TXT等记录: rdata为list/tuple(元素为bytes)，非IP非域名，跳过避免污染
        if isinstance(rdata, (list, tuple)):
            return '', ''
        # A/AAAA记录: rdata为IP字符串; 防御性过滤bytes字面量泄漏(如 "b'xxx'")
        s = str(rdata).strip()
        if s.startswith("b'") or s.startswith('b"'):
            return '', ''
        return 'ip', s

    def _analyze_dns(self, packet, pkt_time: float = 0):
        """分析DNS查询"""
        try:
            dns = packet[DNS]
            
            # 只分析查询请求
            if dns.qr == 0:  # Query
                if dns.qd:
                    for query in dns.qd:
                        if isinstance(query, DNSQR):
                            domain = query.qname.decode('utf-8', errors='ignore').rstrip('.')
                            if domain:
                                entry = self.dns_queries[domain]
                                if entry['first_seen'] is None or pkt_time < entry['first_seen']:
                                    entry['first_seen'] = pkt_time
                                if entry['last_seen'] is None or pkt_time > entry['last_seen']:
                                    entry['last_seen'] = pkt_time
            
            # 分析响应
            elif dns.qr == 1:  # Response
                if dns.qd and dns.an:
                    # 获取查询的域名
                    query_domain = None
                    for query in dns.qd:
                        if isinstance(query, DNSQR):
                            query_domain = query.qname.decode('utf-8', errors='ignore').rstrip('.')
                            break
                    
                    if query_domain:
                        entry = self.dns_queries[query_domain]
                        # 更新时间戳
                        if entry['first_seen'] is None or pkt_time < entry['first_seen']:
                            entry['first_seen'] = pkt_time
                        if entry['last_seen'] is None or pkt_time > entry['last_seen']:
                            entry['last_seen'] = pkt_time
                        # 提取响应中的IP地址(A/AAAA)与CNAME别名
                        for answer in dns.an:
                            try:
                                kind, value = self._extract_dns_answer(answer)
                                if not value:
                                    continue
                                if kind == 'ip':
                                    # A/AAAA记录: 真实IP，计入ips与IP连接
                                    self.dns_queries[query_domain]['ips'].add(value)
                                    self.ip_connections[value]['domains'].add(query_domain)
                                elif kind == 'cname':
                                    # CNAME是域名别名而非IP，单独记录避免污染ips
                                    self.dns_queries[query_domain]['cnames'].add(value)
                            except Exception:
                                pass
        except Exception as e:
            logger.debug(f"分析DNS失败: {e}")
    
    def _analyze_ip(self, packet, pkt_time: float = 0):
        """分析IP层"""
        try:
            ip = packet[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            
            # 统计流量
            packet_size = len(packet)
            
            # 更新源IP统计
            src_entry = self.ip_connections[src_ip]
            src_entry['packet_count'] += 1
            src_entry['bytes'] += packet_size
            if pkt_time > 0:
                if src_entry['first_seen'] is None or pkt_time < src_entry['first_seen']:
                    src_entry['first_seen'] = pkt_time
                if src_entry['last_seen'] is None or pkt_time > src_entry['last_seen']:
                    src_entry['last_seen'] = pkt_time
            
            # 更新目标IP统计
            dst_entry = self.ip_connections[dst_ip]
            dst_entry['packet_count'] += 1
            dst_entry['bytes'] += packet_size
            if pkt_time > 0:
                if dst_entry['first_seen'] is None or pkt_time < dst_entry['first_seen']:
                    dst_entry['first_seen'] = pkt_time
                if dst_entry['last_seen'] is None or pkt_time > dst_entry['last_seen']:
                    dst_entry['last_seen'] = pkt_time
            
        except Exception as e:
            logger.debug(f"分析IP失败: {e}")
    
    def _analyze_tcp(self, packet):
        """分析TCP层"""
        try:
            ip = packet[IP]
            tcp = packet[TCP]
            
            src_ip = ip.src
            dst_ip = ip.dst
            src_port = tcp.sport
            dst_port = tcp.dport
            
            # 记录端口
            self.ip_connections[dst_ip]['ports'].add(dst_port)
            
            # 记录TCP流
            stream = {
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': 'TCP'
            }
            
            # 避免重复记录（只记录一次连接）
            stream_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            if not hasattr(self, '_tcp_stream_set'):
                self._tcp_stream_set = set()
            
            if stream_key not in self._tcp_stream_set:
                self._tcp_stream_set.add(stream_key)
                self.tcp_streams.append(stream)
                
        except Exception as e:
            logger.debug(f"分析TCP失败: {e}")
    
    def _analyze_udp(self, packet):
        """分析UDP层"""
        try:
            ip = packet[IP]
            udp = packet[UDP]
            
            src_ip = ip.src
            dst_ip = ip.dst
            src_port = udp.sport
            dst_port = udp.dport
            
            # 记录端口
            self.ip_connections[dst_ip]['ports'].add(dst_port)
            
            # 记录UDP流
            stream = {
                'src_ip': src_ip,
                'src_port': src_port,
                'dst_ip': dst_ip,
                'dst_port': dst_port,
                'protocol': 'UDP'
            }
            
            stream_key = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}"
            if not hasattr(self, '_udp_stream_set'):
                self._udp_stream_set = set()
            
            if stream_key not in self._udp_stream_set:
                self._udp_stream_set.add(stream_key)
                self.udp_streams.append(stream)

        except Exception as e:
            logger.debug(f"分析UDP失败: {e}")

    def _analyze_http(self, packet, pkt_time: float):
        """
        从HTTP请求中提取完整URL（明文HTTP流量）

        HTTPS流量路径加密无法还原，这里只处理明文HTTP。
        完整URL = http://Host + Path（保留路径与查询参数，不丢信息）。
        """
        try:
            tcp_payload = bytes(packet[TCP].payload)
            if not tcp_payload or len(tcp_payload) < 4:
                return

            # HTTP请求行以请求方法开头
            try:
                first_line = tcp_payload.split(b'\r\n', 1)[0].decode('utf-8', errors='ignore')
            except Exception:
                return

            if not first_line.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ', 'PATCH ')):
                return

            parts = first_line.split(' ')
            if len(parts) < 2:
                return
            method = parts[0]
            path = parts[1]

            # 解析Host头
            host = ''
            try:
                for line in tcp_payload.split(b'\r\n'):
                    line_str = line.decode('utf-8', errors='ignore')
                    if line_str.lower().startswith('host:'):
                        host = line_str[5:].strip()
                        break
            except Exception:
                pass

            if not host:
                return

            # 构建完整URL
            if path.startswith('http://') or path.startswith('https://'):
                full_url = path
            else:
                full_url = f"http://{host}{path}"

            # 去重: 以 "METHOD URL" 为key
            key = f"{method} {full_url}"
            entry = self.http_urls[key]
            entry['method'] = method
            entry['url'] = full_url
            entry['host'] = host
            entry['path'] = path
            entry['count'] += 1
            if entry['first_seen'] is None or pkt_time < entry['first_seen']:
                entry['first_seen'] = pkt_time
            if entry['last_seen'] is None or pkt_time > entry['last_seen']:
                entry['last_seen'] = pkt_time

        except Exception as e:
            logger.debug(f"分析HTTP失败: {e}")

    def _analyze_tls_sni(self, packet, pkt_time: float):
        """从TLS ClientHello中提取SNI服务器名（HTTPS通信的域名）"""
        try:
            tcp_payload = bytes(packet[TCP].payload)
            if not tcp_payload or len(tcp_payload) < 43:
                return
            # TLS握手记录: content_type=0x16
            if tcp_payload[0] != 0x16:
                return

            sni = self._extract_sni(tcp_payload)
            if sni:
                entry = self.tls_snis[sni]
                if entry['first_seen'] is None or pkt_time < entry['first_seen']:
                    entry['first_seen'] = pkt_time
                if entry['last_seen'] is None or pkt_time > entry['last_seen']:
                    entry['last_seen'] = pkt_time
                entry['count'] += 1
        except Exception as e:
            logger.debug(f"分析TLS SNI失败: {e}")

    @staticmethod
    def _extract_sni(payload: bytes) -> str:
        """
        从TLS ClientHello字节流中解析SNI服务器名

        TLS记录层结构:
          content_type(1) + version(2) + length(2)
        Handshake层:
          type(1, 0x01=ClientHello) + length(3) + version(2) + random(32)
          + session_id_len(1) + session_id
          + cipher_suites_len(2) + cipher_suites
          + comp_methods_len(1) + comp_methods
          + extensions_len(2) + extensions
            每个扩展: type(2) + length(2) + data
            SNI扩展 type=0x0000:
              list_len(2) + [name_type(1) + name_len(2) + name]
        """
        try:
            pos = 5  # 跳过TLS记录头
            if pos >= len(payload) or payload[pos] != 0x01:  # ClientHello
                return ''
            pos += 1            # handshake type
            pos += 3            # handshake length
            pos += 2            # client version
            pos += 32           # random

            # session id
            if pos >= len(payload):
                return ''
            session_id_len = payload[pos]
            pos += 1 + session_id_len

            # cipher suites
            if pos + 2 > len(payload):
                return ''
            cipher_len = (payload[pos] << 8) | payload[pos + 1]
            pos += 2 + cipher_len

            # compression methods
            if pos >= len(payload):
                return ''
            comp_len = payload[pos]
            pos += 1 + comp_len

            # extensions
            if pos + 2 > len(payload):
                return ''
            extensions_len = (payload[pos] << 8) | payload[pos + 1]
            pos += 2
            ext_end = pos + extensions_len

            while pos + 4 <= ext_end and pos + 4 <= len(payload):
                ext_type = (payload[pos] << 8) | payload[pos + 1]
                ext_len = (payload[pos + 2] << 8) | payload[pos + 3]
                pos += 4

                if ext_type == 0x0000:  # SNI扩展
                    if pos + 2 > len(payload):
                        break
                    list_len = (payload[pos] << 8) | payload[pos + 1]
                    p = pos + 2
                    list_end = p + list_len
                    while p + 3 <= list_end and p + 3 <= len(payload):
                        name_type = payload[p]
                        name_len = (payload[p + 1] << 8) | payload[p + 2]
                        p += 3
                        if name_type == 0x00 and p + name_len <= len(payload):
                            return payload[p:p + name_len].decode('ascii', errors='ignore')
                        p += name_len
                    break
                pos += ext_len

            return ''
        except Exception:
            return ''

    def generate_report(self, output_file: str) -> Dict:
        """生成分析报告"""
        logger.info("📊 生成分析报告...")
        
        # 查询IP地理位置信息（只查询外网IP）
        logger.info("   查询IP地理位置信息...")
        ip_info_cache = {}
        
        for ip in self.ip_connections.keys():
            # 过滤私有IP
            if not ip.startswith(('10.', '172.', '192.168.', '127.', '169.254.')):
                if ip not in ip_info_cache:
                    ip_info_cache[ip] = self.ip_provider.get_ip_info(ip)
        
        # PCAP时间范围（字符串形式）
        pcap_start_str = self._pkt_time_str(self.pcap_start_time)
        pcap_end_str = self._pkt_time_str(self.pcap_end_time)
        
        # 构建报告数据
        report = {
            'summary': {
                'pcap_file': self.pcap_file,
                'total_packets': len(self.packets) if self.packets else 0,
                'total_domains': len(self.dns_queries),
                'total_ips': len(self.ip_connections),
                'total_tcp_streams': len(self.tcp_streams),
                'total_udp_streams': len(self.udp_streams),
                'total_urls': len(self.http_urls),
                'total_tls_snis': len(self.tls_snis),
                'analyze_time': datetime.now().isoformat(),
                'pcap_start_time': pcap_start_str,
                'pcap_end_time': pcap_end_str
            },
            'domains': [],
            'ips': [],
            'urls': [],
            'tls_snis': [],
            'tcp_streams': self.tcp_streams[:100],  # 只保存前100个
            'udp_streams': self.udp_streams[:100]
        }
        
        # 域名信息（含时间戳与CNAME别名）
        for domain, entry in self.dns_queries.items():
            ips_list = [ip for ip in entry['ips'] if ip != 'pending']
            cnames_list = sorted(entry.get('cnames', set()))
            # 保留有IP或CNAME的域名(此前仅有CNAME的域名会被丢弃)
            if ips_list or cnames_list:
                domain_info = {
                    'domain': domain,
                    'resolved_ips': list(ips_list),
                    'cnames': cnames_list,
                    'ip_count': len(ips_list),
                    'first_seen': self._pkt_time_str(entry['first_seen'] or 0),
                    'last_seen': self._pkt_time_str(entry['last_seen'] or 0),
                    'first_seen_ts': entry['first_seen'] or 0
                }
                report['domains'].append(domain_info)
        
        # 按首次请求时间排序（时间早的在前，无时间的排最后）
        report['domains'].sort(key=lambda x: x.get('first_seen_ts', 0) if x.get('first_seen_ts', 0) > 0 else float('inf'))

        # HTTP完整URL信息（按首次出现时间排序）
        sorted_urls = sorted(self.http_urls.items(),
                             key=lambda x: x[1].get('first_seen') or float('inf'))
        for _, url_entry in sorted_urls:
            report['urls'].append({
                'method': url_entry['method'],
                'url': url_entry['url'],
                'host': url_entry['host'],
                'path': url_entry['path'],
                'count': url_entry['count'],
                'first_seen': self._pkt_time_str(url_entry['first_seen'] or 0),
                'last_seen': self._pkt_time_str(url_entry['last_seen'] or 0),
                'first_seen_ts': url_entry['first_seen'] or 0
            })

        # TLS SNI域名信息（按首次出现时间排序）
        sorted_snis = sorted(self.tls_snis.items(),
                             key=lambda x: x[1].get('first_seen') or float('inf'))
        for sni, sni_entry in sorted_snis:
            report['tls_snis'].append({
                'domain': sni,
                'count': sni_entry['count'],
                'first_seen': self._pkt_time_str(sni_entry['first_seen'] or 0),
                'last_seen': self._pkt_time_str(sni_entry['last_seen'] or 0),
                'first_seen_ts': sni_entry['first_seen'] or 0
            })

        # IP信息（含时间戳和云厂商）
        for ip, info in self.ip_connections.items():
            ip_data = {
                'ip': ip,
                'domains': list(info['domains']) if info['domains'] else [],
                'ports': list(info['ports']),
                'packet_count': info['packet_count'],
                'bytes': info['bytes'],
                'first_seen': self._pkt_time_str(info['first_seen'] or 0),
                'last_seen': self._pkt_time_str(info['last_seen'] or 0),
                'location': ip_info_cache.get(ip, {})
            }
            report['ips'].append(ip_data)
        
        # 按流量排序
        report['ips'].sort(key=lambda x: x['bytes'], reverse=True)
        
        # 保存JSON报告
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        logger.info(f"✅ JSON报告已保存: {output_file}")
        
        # 生成HTML报告
        html_file = output_file.replace('.json', '.html')
        self._generate_html_report(report, html_file)
        
        return report
    
    def _generate_html_report(self, report: Dict, output_file: str):
        """生成HTML格式报告"""
        html_template = """<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>PCAP分析报告</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1 {{ color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }}
        h2 {{ color: #555; margin-top: 30px; }}
        .summary {{ background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0; }}
        .summary-item {{ margin: 10px 0; }}
        .summary-label {{ font-weight: bold; color: #2e7d32; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 12px; text-align: left; }}
        th {{ background: #4CAF50; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        tr:hover {{ background: #f1f1f1; }}
        .badge {{ background: #2196F3; color: white; padding: 3px 8px; border-radius: 3px; font-size: 12px; }}
        .location {{ color: #666; font-size: 13px; }}
        .bytes {{ color: #FF5722; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>📡 PCAP文件分析报告</h1>
        
        <div class="summary">
            <h2>📊 统计摘要</h2>
            <div class="summary-item"><span class="summary-label">PCAP文件:</span> {pcap_file}</div>
            <div class="summary-item"><span class="summary-label">总数据包:</span> {total_packets}</div>
            <div class="summary-item"><span class="summary-label">域名总数:</span> {total_domains}</div>
            <div class="summary-item"><span class="summary-label">IP总数:</span> {total_ips}</div>
            <div class="summary-item"><span class="summary-label">TCP流:</span> {total_tcp_streams}</div>
            <div class="summary-item"><span class="summary-label">UDP流:</span> {total_udp_streams}</div>
            <div class="summary-item"><span class="summary-label">分析时间:</span> {analyze_time}</div>
        </div>
        
        <h2>🌐 DNS解析域名 (Top 20)</h2>
        <table>
            <tr><th>序号</th><th>域名</th><th>解析IP数量</th><th>解析IP地址</th></tr>
            {domains_table}
        </table>
        
        <h2>🌐 通信IP地址 (按流量排序)</h2>
        <table>
            <tr><th>序号</th><th>IP地址</th><th>域名</th><th>端口</th><th>数据包</th><th>流量(字节)</th><th>地理位置</th><th>运营商</th></tr>
            {ips_table}
        </table>
        
        <h2>🔌 TCP连接 (Top 50)</h2>
        <table>
            <tr><th>序号</th><th>源地址</th><th>目标地址</th></tr>
            {tcp_table}
        </table>
        
        <h2>🔌 UDP连接 (Top 50)</h2>
        <table>
            <tr><th>序号</th><th>源地址</th><th>目标地址</th></tr>
            {udp_table}
        </table>
        
        <div style="margin-top: 30px; padding: 20px; background: #fff3e0; border-radius: 5px;">
            <h3>💡 提示</h3>
            <p>• 此报告由PCAP分析工具自动生成</p>
            <p>• 建议使用Wireshark进行深入的流量分析</p>
            <p>• 可按域名或IP过滤特定流量</p>
        </div>
    </div>
</body>
</html>"""
        
        # 生成域名表格
        domains_table = ""
        for i, domain in enumerate(report['domains'][:20], 1):
            ips = ', '.join(domain['resolved_ips'][:3])
            if len(domain['resolved_ips']) > 3:
                ips += f" ... (+{len(domain['resolved_ips'])-3}个)"
            domains_table += f"<tr><td>{i}</td><td>{domain['domain']}</td><td><span class='badge'>{domain['ip_count']}</span></td><td>{ips}</td></tr>"
        
        # 生成IP表格
        ips_table = ""
        for i, ip in enumerate(report['ips'][:30], 1):
            domains = ', '.join(ip['domains'][:2])
            if len(ip['domains']) > 2:
                domains += f" ... (+{len(ip['domains'])-2}个)"
            
            ports = ', '.join(map(str, sorted(ip['ports'])[:5]))
            if len(ip['ports']) > 5:
                ports += f" ... (+{len(ip['ports'])-5}个)"
            
            location = ip.get('location', {})
            location_str = f"{location.get('country', 'N/A')} - {location.get('city', 'N/A')}"
            isp_str = location.get('isp', 'N/A')
            
            ips_table += f"<tr><td>{i}</td><td>{ip['ip']}</td><td>{domains or '-'}</td><td>{ports or '-'}</td><td>{ip['packet_count']}</td><td class='bytes'>{ip['bytes']}</td><td class='location'>{location_str}</td><td class='location'>{isp_str}</td></tr>"
        
        # 生成TCP表格
        tcp_table = ""
        for i, stream in enumerate(report['tcp_streams'][:50], 1):
            tcp_table += f"<tr><td>{i}</td><td>{stream['src_ip']}:{stream['src_port']}</td><td>{stream['dst_ip']}:{stream['dst_port']}</td></tr>"
        
        # 生成UDP表格
        udp_table = ""
        for i, stream in enumerate(report['udp_streams'][:50], 1):
            udp_table += f"<tr><td>{i}</td><td>{stream['src_ip']}:{stream['src_port']}</td><td>{stream['dst_ip']}:{stream['dst_port']}</td></tr>"
        
        # 填充模板
        html_content = html_template.format(
            pcap_file=report['summary']['pcap_file'],
            total_packets=report['summary']['total_packets'],
            total_domains=report['summary']['total_domains'],
            total_ips=report['summary']['total_ips'],
            total_tcp_streams=report['summary']['total_tcp_streams'],
            total_udp_streams=report['summary']['total_udp_streams'],
            analyze_time=report['summary']['analyze_time'],
            domains_table=domains_table,
            ips_table=ips_table,
            tcp_table=tcp_table,
            udp_table=udp_table
        )
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"✅ HTML报告已保存: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description='PCAP文件分析和报告生成工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python pcap_analyzer.py capture.pcap
  python pcap_analyzer.py capture.pcap -o report.json
        """
    )
    
    parser.add_argument('pcap_file', help='PCAP文件路径')
    parser.add_argument('-o', '--output', help='输出报告文件名(JSON格式)')
    
    args = parser.parse_args()
    
    # 检查文件
    if not os.path.exists(args.pcap_file):
        logger.error(f"❌ 文件不存在: {args.pcap_file}")
        return
    
    # 确定输出文件名
    output_file = args.output
    if not output_file:
        pcap_path = Path(args.pcap_file)
        output_file = pcap_path.parent / f"{pcap_path.stem}_report.json"
    
    # 分析PCAP
    analyzer = PCAPAnalyzer(args.pcap_file)
    
    if not analyzer.load_pcap():
        return
    
    analyzer.analyze()
    
    # 生成报告
    report = analyzer.generate_report(str(output_file))
    
    # 打印摘要
    print("\n" + "=" * 60)
    print("📊 PCAP分析报告摘要")
    print("=" * 60)
    print(f"总数据包: {report['summary']['total_packets']}")
    print(f"域名数量: {report['summary']['total_domains']}")
    print(f"IP数量: {report['summary']['total_ips']}")
    print(f"TCP流: {report['summary']['total_tcp_streams']}")
    print(f"UDP流: {report['summary']['total_udp_streams']}")
    print(f"\n报告文件:")
    print(f"  JSON: {output_file}")
    print(f"  HTML: {str(output_file).replace('.json', '.html')}")


if __name__ == '__main__':
    main()