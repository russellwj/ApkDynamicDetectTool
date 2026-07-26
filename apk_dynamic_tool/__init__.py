#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK动态分析工具套件 (ApkDynamicDetectTool)

端到端自动化分析APK的运行时网络行为:
1. 静态解析APK (androguard + aapt + 原始Manifest)
2. 安装到设备, 差集检测真实包名
3. 通过 PCAPdroid 官方API抓包 (无需UI点击)
4. 反复启停 + 自动遍历页面 + 周期截图
5. 解析PCAP提取 DNS/HTTP/TLS SNI/地理位置
6. 生成可视化HTML报告
7. 自动卸载, 保持设备清洁

模块结构:
  adb_helper.ADBHelper               ADB命令封装 (设备/包列表/差集检测)
  apk_analyzer.APKAnalyzer           APK静态解析 (混淆感知多方法融合)
  apk_downloader.ApkDownloader       URL下载APK (HTTP下载+魔数验证)
  chrome_monitor.ChromeMonitor       Chrome CDP监控 (捕获带鉴权的APK下载链接)
  pcapdroid_controller.PCAPdroidController  PCAPdroid Intent API控制
  app_launcher.AppLauncher           精确启动Main Activity
  app_traverser.AppTraverser         深度优先页面遍历
  dialog_handlers                    弹窗/截图/反复启停辅助函数
  pcap_analyzer.PCAPAnalyzer         Scapy解析PCAP流量
  pcap_analyzer.IPInfoProvider       IP地理位置与云厂商识别
  report_generator.ReportGenerator   HTML可视化报告生成
  capture_pipeline.main              端到端流程编排入口

CLI入口(向后兼容):
  python apk_capture_final.py -a app.apk
  python apk_capture_final.py --url https://example.com/app.apk
  python apk_capture_final.py --monitor  # Chrome监控模式
  python pcap_analyzer.py capture.pcap
  python report_generator.py app.apk -t report.json -s screenshots/
  python batch_analyze.py
  python batch_analyze.py --url https://example.com/app1.apk https://example.com/app2.apk
  python batch_analyze.py --monitor --monitor-count 3
"""

from .adb_helper import ADBHelper
from .apk_analyzer import APKAnalyzer
from .apk_downloader import ApkDownloader, ApkDownloadError
from .chrome_monitor import ChromeMonitor, ChromeMonitorError, CapturedRequest
from .pcapdroid_controller import PCAPdroidController
from .app_launcher import AppLauncher
from .app_traverser import AppTraverser
from .dialog_handlers import (
    _close_security_dialogs_adb,
    _close_security_dialogs_ui,
    _take_periodic_screenshots,
    _run_app_with_cycles,
)
from .pcap_analyzer import IPInfoProvider, PCAPAnalyzer
from .report_generator import ReportGenerator

__all__ = [
    'ADBHelper',
    'APKAnalyzer',
    'ApkDownloader',
    'ApkDownloadError',
    'ChromeMonitor',
    'ChromeMonitorError',
    'CapturedRequest',
    'PCAPdroidController',
    'AppLauncher',
    'AppTraverser',
    '_close_security_dialogs_adb',
    '_close_security_dialogs_ui',
    '_take_periodic_screenshots',
    '_run_app_with_cycles',
    'IPInfoProvider',
    'PCAPAnalyzer',
    'ReportGenerator',
]

__version__ = '1.1.0'
