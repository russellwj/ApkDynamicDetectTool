#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
完整报告生成工具
整合APK信息、运行截图和流量分析，生成美观的HTML报告
"""

import json
import os
import zipfile
import hashlib
import base64
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


class ReportGenerator:
    """完整报告生成器"""
    
    def __init__(self):
        self.apk_info = {}
        self.traffic_info = {}
        self.screenshots = []
        self.apk_images = []  # APK内图标与静态图片
    
    def load_apk_info(self, apk_file: str, metadata_file: Optional[str] = None):
        """加载APK基本信息"""
        apk_path = Path(apk_file)
        
        # 基本信息
        self.apk_info = {
            'file_name': apk_path.name,
            'file_size': 0,
            'file_size_mb': 0,
            'md5': '',
            'sha256': '',
            'package_name': '',
            'version_name': '',
            'version_code': '',
            'main_activity': '',
            'permissions': [],
            'signing_info': [],  # 签名信息列表
            'min_sdk': '',
            'target_sdk': '',
            'app_name': '',
            'analyze_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # 计算文件大小和哈希
        if apk_path.exists():
            file_size = apk_path.stat().st_size
            self.apk_info['file_size'] = file_size
            self.apk_info['file_size_mb'] = round(file_size / 1024 / 1024, 2)
            
            # 计算MD5和SHA256
            print("计算APK文件哈希值...")
            md5_hash = hashlib.md5()
            sha256_hash = hashlib.sha256()
            
            with open(apk_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b''):
                    md5_hash.update(chunk)
                    sha256_hash.update(chunk)
            
            self.apk_info['md5'] = md5_hash.hexdigest()
            self.apk_info['sha256'] = sha256_hash.hexdigest()
        
        # 使用androguard提取详细信息（包名、版本、权限、签名等）
        try:
            from androguard.core import apk as andro_apk
            a = andro_apk.APK(str(apk_path))
            
            self.apk_info['package_name'] = a.get_package() or ''
            self.apk_info['version_name'] = a.get_androidversion_name() or ''
            self.apk_info['version_code'] = a.get_androidversion_code() or ''
            self.apk_info['main_activity'] = a.get_main_activity() or ''
            self.apk_info['app_name'] = a.get_app_name() or ''
            self.apk_info['min_sdk'] = str(a.get_min_sdk_version() or '')
            self.apk_info['target_sdk'] = str(a.get_target_sdk_version() or '')
            self.apk_info['permissions'] = list(a.get_permissions() or [])
            
            # 提取签名信息
            self.apk_info['signing_info'] = self._extract_signing_info(a)
            
        except Exception as e:
            print(f"⚠ androguard提取APK信息失败: {e}")
        
        # 从元数据文件加载（作为补充，覆盖androguard的结果）
        if metadata_file and Path(metadata_file).exists():
            try:
                with open(metadata_file, 'r', encoding='utf-8') as f:
                    metadata = json.load(f)
                
                if not self.apk_info['package_name']:
                    self.apk_info['package_name'] = metadata.get('package_name', '')
                if not self.apk_info['main_activity']:
                    self.apk_info['main_activity'] = metadata.get('main_activity', '')
            except:
                pass
    
    def _extract_signing_info(self, apk_obj) -> List[Dict]:
        """使用androguard提取APK签名信息"""
        signing_info = []
        try:
            # 获取所有签名证书
            certificates = apk_obj.get_certificates()
            if not certificates:
                # 尝试v1签名
                try:
                    certificates = apk_obj.get_certificates_der_v3() or apk_obj.get_certificates_der_v2() or []
                except:
                    certificates = []
            
            for cert in certificates:
                cert_info = {
                    'subject': '',
                    'issuer': '',
                    'serial_number': '',
                    'md5': '',
                    'sha1': '',
                    'sha256': '',
                    'not_before': '',
                    'not_after': ''
                }
                
                try:
                    # androguard的证书对象
                    if hasattr(cert, 'subject'):
                        cert_info['subject'] = str(cert.subject.human_friendly) if hasattr(cert.subject, 'human_friendly') else str(cert.subject)
                    if hasattr(cert, 'issuer'):
                        cert_info['issuer'] = str(cert.issuer.human_friendly) if hasattr(cert.issuer, 'human_friendly') else str(cert.issuer)
                    if hasattr(cert, 'serial_number'):
                        cert_info['serial_number'] = str(cert.serial_number)
                    
                    # 哈希值
                    if hasattr(cert, 'sha256'):
                        import hashlib as hl
                        try:
                            cert_info['sha256'] = hl.sha256(cert.sha256).hexdigest() if isinstance(cert.sha256, bytes) else str(cert.sha256)
                        except:
                            pass
                    if hasattr(cert, 'sha1'):
                        import hashlib as hl
                        try:
                            cert_info['sha1'] = hl.sha1(cert.sha1).hexdigest() if isinstance(cert.sha1, bytes) else str(cert.sha1)
                        except:
                            pass
                    
                    # 有效期
                    if hasattr(cert, 'not_valid_before'):
                        cert_info['not_before'] = str(cert.not_valid_before)
                    if hasattr(cert, 'not_valid_after'):
                        cert_info['not_after'] = str(cert.not_valid_after)
                        
                except Exception as e:
                    print(f"⚠ 解析证书失败: {e}")
                
                signing_info.append(cert_info)
        except Exception as e:
            print(f"⚠ 提取签名信息失败: {e}")
        
        return signing_info
    
    def load_traffic_analysis(self, report_file: str):
        """加载流量分析结果"""
        if not Path(report_file).exists():
            return
        
        try:
            with open(report_file, 'r', encoding='utf-8') as f:
                self.traffic_info = json.load(f)
        except:
            pass
    
    def load_screenshots(self, screenshots_dir: str):
        """加载截图并转为base64"""
        screenshots_path = Path(screenshots_dir)
        
        if not screenshots_path.exists():
            return
        
        print(f"加载截图: {screenshots_dir}")
        
        # 支持的图片格式
        image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.bmp']
        
        # 遍历所有图片文件
        for img_file in sorted(screenshots_path.glob('*')):
            if img_file.suffix.lower() in image_extensions:
                try:
                    with open(img_file, 'rb') as f:
                        img_data = base64.b64encode(f.read()).decode()
                    
                    # 确定图片类型
                    img_type = img_file.suffix.lower()
                    if img_type == '.jpg':
                        img_type = '.jpeg'
                    
                    self.screenshots.append({
                        'name': img_file.name,
                        'data': f"data:image/{img_type[1:]};base64,{img_data}"
                    })
                except Exception as e:
                    print(f"加载截图失败 {img_file.name}: {e}")

    def load_apk_images(self, apk_file: str, max_images: int = 20,
                        min_size: int = 1024, max_size: int = 524288):
        """
        从APK中提取应用图标(必须)和静态图片资源

        Args:
            apk_file: APK文件路径
            max_images: 其他静态图片最大数量(不含图标)
            min_size: 最小文件大小(字节)，过滤过小的装饰图片
            max_size: 最大文件大小(字节)，过滤过大的图片
        """
        apk_path = Path(apk_file)
        if not apk_path.exists():
            return

        # 1. 通过androguard获取图标资源引用
        icon_ref = None
        andro_apk_obj = None
        try:
            from androguard.core import apk as andro_apk
            andro_apk_obj = andro_apk.APK(str(apk_path))
            icon_ref = andro_apk_obj.get_app_icon()
        except Exception as e:
            print(f"⚠ 获取应用图标引用失败: {e}")

        image_exts = {'.png', '.jpg', '.jpeg', '.webp', '.gif', '.bmp'}

        try:
            with zipfile.ZipFile(str(apk_path), 'r') as zf:
                entries = zf.namelist()

                # 2. 确定图标条目(图标为必须项)
                icon_entry = None
                if icon_ref and icon_ref in entries:
                    icon_entry = icon_ref
                if not icon_entry:
                    # 兜底: 按常见图标名查找，优先高分辨率
                    dpi_order = ['xxxhdpi', 'xxhdpi', 'xhdpi', 'hdpi', 'mdpi']
                    for dpi in dpi_order:
                        for entry in entries:
                            low = entry.lower()
                            if dpi in low and 'ic_launcher' in low and entry.lower().endswith(('.png', '.webp')):
                                icon_entry = entry
                                break
                        if icon_entry:
                            break
                    # 仍未找到，取任意ic_launcher
                    if not icon_entry:
                        for entry in entries:
                            low = entry.lower()
                            if 'ic_launcher' in low and entry.lower().endswith(('.png', '.webp')):
                                icon_entry = entry
                                break

                if icon_entry:
                    try:
                        data = zf.read(icon_entry)
                        if data:
                            self._add_image(icon_entry, data, is_icon=True)
                    except Exception as e:
                        print(f"⚠ 读取图标失败: {e}")
                else:
                    print("⚠ 未找到应用图标")

                # 3. 提取其他静态图片(大小筛选 + 数量限制)
                other_count = 0
                for entry in entries:
                    if other_count >= max_images:
                        break
                    if entry == icon_entry:
                        continue
                    ext = os.path.splitext(entry)[1].lower()
                    if ext not in image_exts:
                        continue
                    try:
                        info = zf.getinfo(entry)
                        if info.file_size < min_size or info.file_size > max_size:
                            continue
                        data = zf.read(entry)
                        if data:
                            self._add_image(entry, data, is_icon=False)
                            other_count += 1
                    except Exception:
                        continue

            print(f"✅ 提取APK图片: 图标{'1' if icon_entry else '0'}个 + 其他{len(self.apk_images) - (1 if icon_entry else 0)}个")
        except Exception as e:
            print(f"⚠ 提取APK图片失败: {e}")

    def _add_image(self, name: str, data: bytes, is_icon: bool = False):
        """将图片字节转为base64并加入列表"""
        ext = os.path.splitext(name)[1].lower()
        mime_map = {
            '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg',
            '.webp': 'image/webp', '.gif': 'image/gif', '.bmp': 'image/bmp'
        }
        mime = mime_map.get(ext, 'image/png')
        b64 = base64.b64encode(data).decode()
        # 显示名只保留文件名
        display_name = os.path.basename(name) if '/' in name else name
        self.apk_images.append({
            'name': display_name,
            'path': name,
            'mime': mime,
            'data': f"data:{mime};base64,{b64}",
            'is_icon': is_icon,
            'size': len(data)
        })

    @staticmethod
    def _is_private_ip(ip: str) -> bool:
        """判断是否为内网/私有IP地址"""
        try:
            parts = ip.split('.')
            if len(parts) != 4:
                return False
            a, b = int(parts[0]), int(parts[1])
            if a == 10:
                return True
            if a == 172 and 16 <= b <= 31:
                return True
            if a == 192 and b == 168:
                return True
            if a == 127:
                return True
            if a == 169 and b == 254:
                return True
            return False
        except Exception:
            return False

    def generate_html_report(self, output_file: str):
        """生成完整的HTML报告"""
        
        # 构建HTML内容
        html_content = self._build_html()
        
        # 保存报告
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"✅ HTML报告已生成: {output_file}")
    
    def _build_html(self) -> str:
        """构建HTML内容"""

        # APK基本信息部分
        apk_section = self._build_apk_section()

        # APK图标与图片资源部分
        images_section = self._build_images_section()

        # 截图部分
        screenshots_section = self._build_screenshots_section()

        # 流量分析部分
        traffic_section = self._build_traffic_section()

        # 组装完整HTML
        html = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>APK安全分析报告 - {self.apk_info['file_name']}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        
        .header h1 {{
            font-size: 32px;
            margin-bottom: 10px;
        }}
        
        .header .subtitle {{
            font-size: 16px;
            opacity: 0.9;
        }}
        
        .content {{
            padding: 30px;
        }}
        
        .section {{
            margin-bottom: 40px;
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
        }}
        
        .section-header {{
            background: #f8f9fa;
            padding: 15px 20px;
            border-bottom: 1px solid #e0e0e0;
            font-size: 20px;
            font-weight: bold;
            color: #667eea;
            display: flex;
            align-items: center;
        }}
        
        .section-header .icon {{
            font-size: 24px;
            margin-right: 10px;
        }}
        
        .section-content {{
            padding: 20px;
        }}
        
        .info-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 15px;
        }}
        
        .info-item {{
            display: flex;
            padding: 10px;
            background: #f8f9fa;
            border-radius: 5px;
        }}
        
        .info-label {{
            font-weight: bold;
            color: #555;
            min-width: 120px;
        }}
        
        .info-value {{
            color: #333;
            word-break: break-all;
        }}
        
        .permissions-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
            margin-top: 10px;
        }}
        
        .permission-tag {{
            background: #e3f2fd;
            color: #1976d2;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 12px;
        }}
        
        .screenshots-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 15px;
        }}
        
        .screenshot-item {{
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            overflow: hidden;
            transition: transform 0.3s;
        }}
        
        .screenshot-item:hover {{
            transform: translateY(-5px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }}
        
        .screenshot-item img {{
            width: 100%;
            height: auto;
            display: block;
        }}
        
        .screenshot-item .caption {{
            padding: 8px;
            background: #f8f9fa;
            text-align: center;
            font-size: 12px;
            color: #666;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        
        .stat-card {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        
        .stat-number {{
            font-size: 32px;
            font-weight: bold;
            margin-bottom: 5px;
        }}
        
        .stat-label {{
            font-size: 14px;
            opacity: 0.9;
        }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }}
        
        th, td {{
            border: 1px solid #e0e0e0;
            padding: 12px;
            text-align: left;
        }}
        
        th {{
            background: #667eea;
            color: white;
            font-weight: bold;
        }}
        
        tr:nth-child(even) {{
            background: #f8f9fa;
        }}
        
        tr:hover {{
            background: #e3f2fd;
        }}
        
        .badge {{
            display: inline-block;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
        }}
        
        .badge-blue {{ background: #2196F3; color: white; }}
        .badge-green {{ background: #4CAF50; color: white; }}
        .badge-orange {{ background: #FF9800; color: white; }}
        .badge-red {{ background: #F44336; color: white; }}
        
        .footer {{
            background: #f8f9fa;
            padding: 20px;
            text-align: center;
            color: #666;
            font-size: 12px;
        }}
        
        .alert {{
            padding: 15px;
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            margin: 20px 0;
            border-radius: 4px;
        }}
        
        .no-data {{
            text-align: center;
            padding: 40px;
            color: #999;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📱 APK安全分析报告</h1>
            <div class="subtitle">全面分析应用行为与网络流量</div>
        </div>
        
        <div class="content">
            {apk_section}

            {images_section}

            {screenshots_section}

            {traffic_section}
        </div>
        
        <div class="footer">
            <p>报告生成时间: {self.apk_info['analyze_time']}</p>
            <p>本报告由自动化工具生成，仅供安全分析参考</p>
        </div>
    </div>
</body>
</html>"""
        
        return html
    
    def _build_apk_section(self) -> str:
        """构建APK信息部分"""
        
        # 权限HTML
        permissions_html = ""
        if self.apk_info.get('permissions'):
            perms = [f'<span class="permission-tag">{p}</span>' for p in self.apk_info['permissions'][:30]]
            permissions_html = f"""
            <div style="margin-top: 15px;">
                <div class="info-label">申请权限 ({len(self.apk_info['permissions'])}个):</div>
                <div class="permissions-list">{''.join(perms)}</div>
            </div>"""
        
        # 签名信息HTML
        signing_html = ""
        signing_info = self.apk_info.get('signing_info', [])
        if signing_info:
            signing_rows = ""
            for i, cert in enumerate(signing_info, 1):
                subject = cert.get('subject', 'N/A')
                issuer = cert.get('issuer', 'N/A')
                serial = cert.get('serial_number', 'N/A')
                sha256 = cert.get('sha256', 'N/A')
                sha1 = cert.get('sha1', 'N/A')
                not_before = cert.get('not_before', 'N/A')
                not_after = cert.get('not_after', 'N/A')
                
                signing_rows += f"""
                <tr>
                    <td>{i}</td>
                    <td style="font-size: 11px; word-break: break-all;">{subject}</td>
                    <td style="font-size: 11px; word-break: break-all;">{issuer}</td>
                    <td style="font-size: 10px; word-break: break-all;">{sha256}</td>
                    <td style="font-size: 10px; word-break: break-all;">{sha1}</td>
                    <td style="font-size: 11px;">{not_before}</td>
                    <td style="font-size: 11px;">{not_after}</td>
                </tr>"""
            
            signing_html = f"""
            <div style="margin-top: 20px;">
                <div class="info-label">签名证书 ({len(signing_info)}个):</div>
                <table style="margin-top: 10px;">
                    <tr>
                        <th style="width: 40px;">序号</th>
                        <th>Subject</th>
                        <th>Issuer</th>
                        <th>SHA256</th>
                        <th>SHA1</th>
                        <th style="width: 130px;">生效时间</th>
                        <th style="width: 130px;">失效时间</th>
                    </tr>
                    {signing_rows}
                </table>
            </div>"""
        
        html = f"""
        <div class="section">
            <div class="section-header">
                <span class="icon">📱</span>
                APK基本信息
            </div>
            <div class="section-content">
                <div class="info-grid">
                    <div class="info-item">
                        <span class="info-label">文件名:</span>
                        <span class="info-value">{self.apk_info['file_name']}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">应用名:</span>
                        <span class="info-value">{self.apk_info.get('app_name', '-')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">文件大小:</span>
                        <span class="info-value">{self.apk_info['file_size_mb']} MB ({self.apk_info['file_size']} bytes)</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">包名:</span>
                        <span class="info-value">{self.apk_info['package_name']}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">版本:</span>
                        <span class="info-value">{self.apk_info['version_name']} ({self.apk_info['version_code']})</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">主Activity:</span>
                        <span class="info-value" style="font-size: 12px;">{self.apk_info['main_activity']}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">最低SDK版本:</span>
                        <span class="info-value">{self.apk_info.get('min_sdk', '-')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">目标SDK版本:</span>
                        <span class="info-value">{self.apk_info.get('target_sdk', '-')}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">MD5:</span>
                        <span class="info-value" style="font-size: 12px; word-break: break-all;">{self.apk_info['md5']}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">SHA256:</span>
                        <span class="info-value" style="font-size: 11px; word-break: break-all;">{self.apk_info['sha256']}</span>
                    </div>
                    <div class="info-item">
                        <span class="info-label">分析时间:</span>
                        <span class="info-value">{self.apk_info['analyze_time']}</span>
                    </div>
                </div>
                {permissions_html}
                {signing_html}
            </div>
        </div>"""
        
        return html
    
    def _build_screenshots_section(self) -> str:
        """构建截图部分"""
        
        if not self.screenshots:
            return """
            <div class="section">
                <div class="section-header">
                    <span class="icon">📸</span>
                    运行时截图
                </div>
                <div class="section-content">
                    <div class="no-data">暂无截图</div>
                </div>
            </div>"""
        
        screenshots_html = ""
        for screenshot in self.screenshots:
            screenshots_html += f"""
            <div class="screenshot-item">
                <img src="{screenshot['data']}" alt="{screenshot['name']}">
                <div class="caption">{screenshot['name']}</div>
            </div>"""
        
        html = f"""
        <div class="section">
            <div class="section-header">
                <span class="icon">📸</span>
                运行时截图 ({len(self.screenshots)}张)
            </div>
            <div class="section-content">
                <div class="screenshots-grid">
                    {screenshots_html}
                </div>
            </div>
        </div>"""

        return html

    def _build_images_section(self) -> str:
        """构建APK图标与静态图片资源部分"""
        if not self.apk_images:
            return """
            <div class="section">
                <div class="section-header">
                    <span class="icon">🎨</span>
                    APK图标与图片资源
                </div>
                <div class="section-content">
                    <div class="no-data">未提取到图片资源</div>
                </div>
            </div>"""

        icons = [img for img in self.apk_images if img['is_icon']]
        others = [img for img in self.apk_images if not img['is_icon']]

        # 图标单独突出展示(必须项)
        icon_html = '<div class="no-data">未找到应用图标</div>'
        if icons:
            icon = icons[0]
            icon_html = f"""
            <div style="text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                <img src="{icon['data']}" style="max-width: 128px; max-height: 128px; border-radius: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.2);">
                <div style="margin-top: 10px; color: #555; font-size: 13px;">应用图标 · {icon['name']} · {icon['size']//1024}KB</div>
            </div>"""

        # 其他静态图片网格
        others_html = ""
        if others:
            items = ""
            for img in others:
                items += f"""
                <div class="screenshot-item">
                    <img src="{img['data']}" alt="{img['name']}">
                    <div class="caption">{img['name']} · {img['size']//1024}KB</div>
                </div>"""
            others_html = f"""
            <h3 style="margin-top: 25px; margin-bottom: 10px; color: #555;">🖼️ 静态图片资源 ({len(others)}个)</h3>
            <div class="screenshots-grid">{items}</div>"""
        else:
            others_html = '<div style="margin-top:15px;" class="no-data">无其他符合条件的图片资源</div>'

        html = f"""
        <div class="section">
            <div class="section-header">
                <span class="icon">🎨</span>
                APK图标与图片资源
            </div>
            <div class="section-content">
                {icon_html}
                {others_html}
            </div>
        </div>"""

        return html

    def _cloud_badge_html(self, location: Dict) -> str:
        """生成云厂商徽章HTML（基于location字典）"""
        return self._cloud_badge_html_simple(
            location.get('cloud_provider', ''),
            location.get('cloud_category', '')
        )

    @staticmethod
    def _cloud_badge_html_simple(cloud_provider: str, cloud_category: str) -> str:
        """
        生成云厂商徽章HTML（直接传参版，供统一表批量调用）

        背景色规则:
        - 华为云: 红色
        - 阿里云/腾讯云/AWS: 黄色
        - 国内移动运营商(移动/联通/电信): 绿色
        - 其他云: 灰色
        - 未识别: 灰色"-"
        """
        if not cloud_provider:
            return '<span style="color: #999; font-size: 12px;">-</span>'

        # 背景色映射
        color_map = {
            'huawei': '#d32f2f',      # 红色
            'aliyun': '#f9a825',      # 黄色
            'tencent': '#f9a825',     # 黄色
            'aws': '#f9a825',         # 黄色
            'operator': '#43a047',    # 绿色
            'other': '#757575',       # 灰色
        }

        bg_color = color_map.get(cloud_category, '#757575')
        text_color = 'white' if cloud_category in ['huawei', 'operator', 'other'] else '#333'

        return (f'<span style="background-color: {bg_color}; color: {text_color}; '
                f'padding: 3px 8px; border-radius: 4px; font-size: 12px; '
                f'font-weight: bold; display: inline-block; margin: 1px;">{cloud_provider}</span>')
    
    def _build_traffic_section(self) -> str:
        """构建流量分析部分（统一通信记录表，整合域名/IP/协议/URL/地理/厂商/时间）"""
        if not self.traffic_info:
            return """
            <div class="section">
                <div class="section-header">
                    <span class="icon">🌐</span>
                    网络流量分析
                </div>
                <div class="section-content">
                    <div class="no-data">暂无流量分析数据</div>
                </div>
            </div>"""

        summary = self.traffic_info.get('summary', {})

        # 统计卡片
        stats_html = f"""
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{summary.get('total_packets', 0)}</div>
                <div class="stat-label">总数据包</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{summary.get('total_urls', 0)}</div>
                <div class="stat-label">HTTP完整URL</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{summary.get('total_tls_snis', 0)}</div>
                <div class="stat-label">HTTPS域名</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{summary.get('total_domains', 0)}</div>
                <div class="stat-label">DNS域名</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{summary.get('total_ips', 0)}</div>
                <div class="stat-label">IP数量</div>
            </div>
        </div>"""

        # 统一通信记录表（合并原 HTTP URL / HTTPS SNI / DNS / IP 四张分表，消除重复信息）
        unified_table = self._build_unified_traffic_table()

        html = f"""
        <div class="section">
            <div class="section-header">
                <span class="icon">🌐</span>
                网络流量分析
            </div>
            <div class="section-content">
                {stats_html}

                {unified_table}

                <div class="alert" style="margin-top: 30px;">
                    <strong>💡 提示：</strong>
                    表中按域名聚合 HTTP/HTTPS/DNS/IP 全量信息：HTTP 展示完整URL(含路径与参数)；HTTPS 仅可见域名(SNI)，路径加密不可见。
                    建议使用 Wireshark 打开原始 PCAP 文件进行深入分析。
                </div>
            </div>
        </div>"""

        return html

    def _build_unified_traffic_table(self) -> str:
        """
        构建统一通信记录表

        以域名为粒度聚合：协议、请求类型、URL/路径、DNS解析IP、地理位置、归属厂商、请求次数、请求时间。
        取代原 HTTP URL / HTTPS SNI / DNS域名 / IP地址 四张分表，消除重复信息。
        """
        records = self._collect_unified_records()
        if not records:
            return '<div class="no-data">暂无通信记录</div>'

        rows_html = ""
        for i, rec in enumerate(records, 1):
            rows_html += self._render_unified_row(i, rec)

        return f"""
        <h3 style="margin-top: 20px; margin-bottom: 10px;">📋 通信记录汇总（共{len(records)}个域名，按首次请求时间排序）</h3>
        <table>
            <tr>
                <th style="width: 40px;">序号</th>
                <th>域名</th>
                <th style="width: 70px;">协议</th>
                <th style="width: 90px;">请求类型</th>
                <th>URL/路径</th>
                <th>DNS解析IP</th>
                <th>地理位置</th>
                <th style="width: 90px;">归属厂商</th>
                <th style="width: 60px;">次数</th>
                <th style="width: 160px;">请求时间</th>
            </tr>
            {rows_html}
        </table>"""

    def _render_unified_row(self, index: int, rec: Dict) -> str:
        """渲染统一表的一行HTML"""
        # 协议徽章(HTTP蓝/HTTPS橙)
        proto_badges = ''.join(
            f'<span class="badge {"badge-blue" if p == "HTTP" else "badge-orange"}" style="margin: 1px;">{p}</span>'
            for p in rec['protocols']
        ) or '<span style="color: #999; font-size: 12px;">DNS</span>'

        # 请求类型(方法)
        method_str = ', '.join(rec['methods']) or '-'

        # URL/路径列
        url_str = self._format_url_cell(rec)

        # DNS解析IP(完整不省略)
        ip_str = ', '.join(rec['resolved_ips']) if rec['resolved_ips'] else '-'

        # 地理位置(多IP去重合并)
        loc_str = '<br>'.join(rec['locations']) if rec['locations'] else '-'

        # 归属厂商徽章(多厂商合并)
        prov_str = ''.join(
            self._cloud_badge_html_simple(name, cat)
            for name, cat in rec['cloud_providers']
        ) or '<span style="color: #999; font-size: 12px;">-</span>'

        # 请求时间(首次 ~ 末次)
        if rec['first_seen'] and rec['last_seen'] and rec['first_seen'] != rec['last_seen']:
            time_str = f"{rec['first_seen']} ~ {rec['last_seen']}"
        elif rec['first_seen']:
            time_str = rec['first_seen']
        else:
            time_str = '-'

        # CNAME别名(DNS域名跳转链，小字展示在域名下方)
        cname_str = ''
        if rec.get('cnames'):
            cnames = rec['cnames'][:3]
            cname_str = ''.join(
                f'<div style="font-size: 10px; color: #888; font-weight: normal;">↳ {c}</div>'
                for c in cnames
            )
            if len(rec['cnames']) > 3:
                cname_str += f'<div style="font-size: 10px; color: #999;">... +{len(rec["cnames"]) - 3}</div>'

        return f"""
            <tr>
                <td>{index}</td>
                <td style="word-break: break-all; font-weight: bold;">{rec['domain']}{cname_str}</td>
                <td>{proto_badges}</td>
                <td style="font-size: 11px;">{method_str}</td>
                <td>{url_str}</td>
                <td style="font-size: 11px; word-break: break-all;">{ip_str}</td>
                <td style="font-size: 11px;">{loc_str}</td>
                <td>{prov_str}</td>
                <td><span class="badge badge-green">{rec['request_count']}</span></td>
                <td style="font-size: 11px;">{time_str}</td>
            </tr>"""

    @staticmethod
    def _format_url_cell(rec: Dict) -> str:
        """格式化URL列：HTTP展示完整URL(最多3条)，HTTPS说明路径加密"""
        if rec['http_urls']:
            lines = []
            for u in rec['http_urls'][:3]:
                method = u.get('method', '')
                url = u.get('url', '')
                lines.append(
                    f"<div style='font-size: 11px; word-break: break-all;'>"
                    f"<b>{method}</b> {url}</div>"
                )
            if len(rec['http_urls']) > 3:
                lines.append(
                    f"<div style='color: #999; font-size: 11px;'>"
                    f"... +{len(rec['http_urls']) - 3} 个URL</div>"
                )
            return ''.join(lines)
        if 'HTTPS' in rec['protocols']:
            return (f"<span style='color: #999; font-size: 11px;'>"
                    f"https://{rec['domain']}/ (路径加密不可见)</span>")
        return '-'

    def _collect_unified_records(self) -> List[Dict]:
        """
        聚合所有通信记录，以域名为粒度整合 HTTP/HTTPS/DNS/IP 信息

        数据来源:
          - dns_queries  -> 域名的解析IP与时间
          - tls_snis     -> HTTPS通信域名与连接次数
          - http_urls    -> HTTP完整URL(含路径参数)
          - ip_connections(反向) -> 域名关联的IP地理位置与厂商

        Returns:
            域名聚合记录列表，按首次请求时间戳升序排序
        """
        # 反向索引: 域名 -> 关联的IP信息列表(含location/厂商)
        domain_to_ips = defaultdict(list)
        for ip_info in self.traffic_info.get('ips', []):
            for domain in ip_info.get('domains', []):
                domain_to_ips[domain].append(ip_info)

        dns_map = {d['domain']: d for d in self.traffic_info.get('domains', [])}
        sni_map = {s['domain']: s for s in self.traffic_info.get('tls_snis', [])}

        http_map = defaultdict(list)
        for url_info in self.traffic_info.get('urls', []):
            host = url_info.get('host', '')
            if host:
                http_map[host].append(url_info)

        # 合并所有域名来源(去重)
        all_domains = set()
        all_domains.update(dns_map.keys())
        all_domains.update(sni_map.keys())
        all_domains.update(http_map.keys())
        all_domains.update(domain_to_ips.keys())

        records = [
            self._build_domain_record(domain, dns_map, sni_map, http_map, domain_to_ips)
            for domain in all_domains
        ]
        # 按首次请求时间戳排序(无时间的排最后)
        records.sort(
            key=lambda x: x.get('first_seen_ts', 0) if x.get('first_seen_ts', 0) > 0 else float('inf')
        )
        return records

    @staticmethod
    def _is_clean_ip(ip) -> bool:
        """过滤bytes字面量脏数据(如 "b'xxx.'")与空值

        历史JSON中DNS的CNAME应答曾被误当IP存入resolved_ips，
        str(bytes)产生 "b'xxx.'" 形式字符串。此处做防御性清洗，
        确保即使读入旧数据也不会把脏数据渲染到报告。
        """
        if not ip:
            return False
        s = str(ip)
        return not (s.startswith("b'") or s.startswith('b"'))

    def _build_domain_record(self, domain: str, dns_map: Dict, sni_map: Dict,
                              http_map: Dict, domain_to_ips: Dict) -> Dict:
        """构建单个域名的聚合记录"""
        dns_info = dns_map.get(domain, {})
        sni_info = sni_map.get(domain, {})
        http_urls = http_map.get(domain, [])
        ip_infos = domain_to_ips.get(domain, [])

        # 协议
        protocols = []
        if http_urls:
            protocols.append('HTTP')
        if sni_info:
            protocols.append('HTTPS')

        # 请求方法(去重排序)
        methods = sorted({u.get('method') for u in http_urls if u.get('method')})
        if sni_info:
            methods.append('TLS SNI')
        if not methods and dns_info:
            methods.append('DNS查询')

        # DNS解析IP(优先用DNS解析结果，回退用IP连接的域名反查)
        # 防御性清洗: 过滤历史数据中可能残留的 "b'xxx.'" 脏字符串
        resolved_ips = [ip for ip in dns_info.get('resolved_ips', []) if self._is_clean_ip(ip)]
        if not resolved_ips:
            resolved_ips = [ip['ip'] for ip in ip_infos if self._is_clean_ip(ip.get('ip'))]

        # CNAME别名(DNS响应中的域名别名，已清洗，非IP)
        cnames = dns_info.get('cnames', [])

        # 地理位置和厂商聚合
        locations, cloud_providers = self._aggregate_ip_locations(ip_infos)

        # 请求次数(HTTP URL次数 + HTTPS连接次数)
        request_count = sum(u.get('count', 0) for u in http_urls)
        if sni_info:
            request_count += sni_info.get('count', 0)

        # 请求时间聚合(取所有来源最早/最晚)
        first_ts, first_seen, last_seen = self._aggregate_time(dns_info, sni_info, http_urls)

        return {
            'domain': domain,
            'protocols': protocols,
            'methods': methods,
            'http_urls': http_urls,
            'resolved_ips': resolved_ips,
            'cnames': cnames,
            'locations': locations,
            'cloud_providers': cloud_providers,
            'request_count': request_count,
            'first_seen': first_seen,
            'last_seen': last_seen,
            'first_seen_ts': first_ts,
        }

    @staticmethod
    def _aggregate_ip_locations(ip_infos: List[Dict]) -> Tuple[List[str], List[Tuple[str, str]]]:
        """
        聚合IP地理位置和云厂商

        Returns:
            (去重地理位置列表, 去重(厂商名,类别)列表)
        """
        locations = []
        providers = []
        seen_locs = set()
        seen_provs = set()

        for ip_info in ip_infos:
            loc = ip_info.get('location', {})
            country = (loc.get('country') or '').strip()
            city = (loc.get('city') or '').strip()
            if country and country != 'N/A':
                loc_str = f"{country} {city}".strip() if city else country
                if loc_str not in seen_locs:
                    seen_locs.add(loc_str)
                    locations.append(loc_str)

            prov = loc.get('cloud_provider', '')
            cat = loc.get('cloud_category', '')
            if prov and prov not in seen_provs:
                seen_provs.add(prov)
                providers.append((prov, cat))

        return locations, providers

    @staticmethod
    def _aggregate_time(dns_info: Dict, sni_info: Dict,
                        http_urls: List[Dict]) -> Tuple[float, str, str]:
        """
        聚合多来源的请求时间

        Returns:
            (排序时间戳, 首次时间字符串, 末次时间字符串)
            时间字符串为 HH:MM:SS 格式，可直接字符串比较大小
        """
        ts_candidates = []  # (ts, first_str, last_str)
        if dns_info.get('first_seen_ts', 0) and dns_info['first_seen_ts'] > 0:
            ts_candidates.append((dns_info['first_seen_ts'],
                                  dns_info.get('first_seen', ''),
                                  dns_info.get('last_seen', '')))
        if sni_info.get('first_seen_ts', 0) and sni_info['first_seen_ts'] > 0:
            ts_candidates.append((sni_info['first_seen_ts'],
                                  sni_info.get('first_seen', ''),
                                  sni_info.get('last_seen', '')))
        for u in http_urls:
            if u.get('first_seen_ts', 0) and u['first_seen_ts'] > 0:
                ts_candidates.append((u['first_seen_ts'],
                                      u.get('first_seen', ''),
                                      u.get('last_seen', '')))

        if not ts_candidates:
            return 0, '', ''

        first_ts = min(t[0] for t in ts_candidates)
        first_str = min((t[1] for t in ts_candidates if t[1]), default='')
        last_str = max((t[2] for t in ts_candidates if t[2]), default='')
        return first_ts, first_str, last_str


def main():
    import argparse
    
    parser = argparse.ArgumentParser(
        description='生成完整的APK分析报告（整合APK信息、截图和流量分析）'
    )
    
    parser.add_argument('apk_file', help='APK文件路径')
    parser.add_argument('-t', '--traffic', help='流量分析JSON报告文件')
    parser.add_argument('-s', '--screenshots', help='截图目录')
    parser.add_argument('-o', '--output', help='输出HTML报告文件名')
    
    args = parser.parse_args()
    
    # 确定输出文件
    output_file = args.output
    if not output_file:
        apk_path = Path(args.apk_file)
        output_file = apk_path.parent / f"{apk_path.stem}_complete_report.html"
    
    # 创建报告生成器
    generator = ReportGenerator()
    
    # 加载APK信息
    print(f"📱 加载APK信息: {args.apk_file}")
    generator.load_apk_info(args.apk_file)
    
    # 加载流量分析
    if args.traffic and Path(args.traffic).exists():
        print(f"🌐 加载流量分析: {args.traffic}")
        generator.load_traffic_analysis(args.traffic)
    
    # 加载截图
    if args.screenshots and Path(args.screenshots).exists():
        generator.load_screenshots(args.screenshots)
    
    # 生成报告
    generator.generate_html_report(str(output_file))
    
    print(f"\n✅ 报告生成完成!")
    print(f"📄 HTML报告: {output_file}")


if __name__ == '__main__':
    main()