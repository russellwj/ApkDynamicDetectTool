#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
端到端流程编排: APK安装→抓包→运行→流量分析→报告生成→卸载
"""

import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

import argparse
import os
import time
import json
from pathlib import Path
from datetime import datetime
from typing import Optional

try:
    import uiautomator2 as u2
    from uiautomator2 import Device  # noqa: F401
    HAS_UI2 = True
except ImportError:
    HAS_UI2 = False
    logger.error("❌ uiautomator2未安装，请运行: pip install uiautomator2")

try:
    from androguard.core import apk  # noqa: F401
    HAS_ANDROGUARD = True
except ImportError:
    HAS_ANDROGUARD = False
    logger.warning("⚠ androguard未安装，部分功能可能受限，建议运行: pip install androguard")

from .adb_helper import ADBHelper
from .apk_analyzer import APKAnalyzer
from .pcapdroid_controller import PCAPdroidController
from .app_launcher import AppLauncher
from .app_traverser import AppTraverser
from .dialog_handlers import (
    _close_security_dialogs_adb,
    _close_security_dialogs_ui,
    _take_periodic_screenshots,
    _run_app_with_cycles,
)

from . import pcap_analyzer as _pcap_analyzer_mod
from . import report_generator as _report_generator_mod


def main():
    parser = argparse.ArgumentParser(
        description='APK安装、自动遍历与运行时抓包工具(完整自动化版)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python apk_capture_final.py -a app.apk
  python apk_capture_final.py -a app.apk --max-depth 30
  python apk_capture_final.py -p com.example.app --no-install

依赖:
  pip install uiautomator2
        """
    )
    
    parser.add_argument('-a', '--apk', help='APK文件路径')
    parser.add_argument('-p', '--package', help='指定包名')
    parser.add_argument('-o', '--output', default='./output', help='输出目录')
    parser.add_argument('--max-depth', type=int, default=0, help='遍历深度，0表示不遍历，只等待wait_time秒 (默认: 0)')
    parser.add_argument('--wait-time', type=int, default=30, help='应用启动后总运行时间（秒），max_depth为0时有效 (默认: 30)')
    parser.add_argument('--screenshot-interval', type=int, default=10, help='截图间隔时间（秒） (默认: 10)')
    parser.add_argument('--restart-count', type=int, default=2, help='应用反复启停次数，0表示只启动一次不重启 (默认: 2，配合wait_time=30即启动3次每次10秒)')
    parser.add_argument('--no-install', action='store_true', help='不安装APK')
    parser.add_argument('-s', '--serial', help='指定设备序列号')
    parser.add_argument('--clear-data', action='store_true', help='清除应用数据')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("APK安装、自动遍历与运行时抓包工具(完整自动化版)")
    print("=" * 60)
    
    # 检查依赖
    if not HAS_UI2:
        print("\n❌ 缺少依赖，请安装:")
        print("   pip install uiautomator2")
        return
    
    if not HAS_ANDROGUARD:
        print("\n⚠ 建议安装androguard以获得更好的APK解析能力:")
        print("   pip install androguard")
        print("   (将使用备用方法解析APK)")
    
    # 初始化ADB
    adb = ADBHelper()
    if args.serial:
        adb.device_id = args.serial
    
    if not adb.check_device():
        return
    
    # 获取包名和Activity
    package_name = args.package
    main_activity = None
    apk_file_name = None
    
    if args.apk:
        apk_info = APKAnalyzer.get_package_info(args.apk)
        if apk_info.get('package'):
            package_name = apk_info['package']
            main_activity = apk_info.get('activity')
        
        # 提取APK文件名（不含扩展名）
        apk_file_name = os.path.splitext(os.path.basename(args.apk))[0]
    
    if not package_name:
        logger.error("❌ 请提供APK文件(-a)或包名(-p)")
        return
    
    logger.info(f"📱 目标应用: {package_name}")
    if main_activity:
        logger.info(f"   主Activity: {main_activity}")
    
    # 创建输出目录（按APK文件名+时间戳）
    base_output_dir = Path(args.output)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    if apk_file_name:
        dir_name = f"{apk_file_name}_{timestamp}"
    else:
        dir_name = f"{package_name}_{timestamp}"
    
    output_dir = base_output_dir / dir_name
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # 创建子目录
    screenshots_dir = output_dir / 'screenshots'
    screenshots_dir.mkdir(exist_ok=True)
    
    logger.info(f"📁 输出目录: {output_dir.absolute()}")
    
    # 初始化PCAPdroid控制器（稍后传入device）
    pcapdroid = PCAPdroidController(adb)
    if not pcapdroid.check_installation():
        return
    
    # 安装APK
    if args.apk and not args.no_install:
        logger.info("\n" + "=" * 60)
        logger.info("📦 安装APK")
        logger.info("=" * 60)
        
        # 安装前等待系统反应
        logger.info("   ⏳ 等待系统准备就绪...")
        time.sleep(2)
        
        # 安装前检查并关闭弹窗
        logger.info("   🔍 检查安装前的系统弹窗...")
        _close_security_dialogs_adb(adb)
        time.sleep(1)

        # 清理所有候选包名的旧安装残留(确保差集检测干净，避免静态解析错误包名残留干扰)
        candidate_pkgs = apk_info.get('all_candidates', []) if 'apk_info' in locals() else []
        if candidate_pkgs:
            logger.info(f"   🧹 清理可能的旧安装残留({len(candidate_pkgs)}个候选包名)...")
            for cand_pkg in candidate_pkgs:
                ret, stdout, _ = adb.run_adb(['uninstall', cand_pkg], timeout=30)
                if ret == 0 and 'Success' in stdout:
                    logger.info(f"      已清理残留: {cand_pkg}")
            time.sleep(2)

        if args.clear_data:
            adb.run_adb(['shell', 'pm', 'clear', package_name])

        # 记录安装前的包列表(用于安装后差集验证真实包名)
        before_pkgs = adb.get_installed_packages()

        ret, stdout, _ = adb.run_adb(['install', '-r', args.apk], timeout=120)
        if ret == 0 and 'Success' in stdout:
            logger.info("✅ APK安装成功")
        else:
            logger.warning("⚠ APK安装失败，尝试继续...")

        # 等待可能的安全弹窗出现
        time.sleep(3)

        # 安装后差集验证: 用系统注册的真实包名纠正静态解析(系统ground truth最准)
        real_pkg = adb.detect_installed_package(before_pkgs, package_name)
        if real_pkg:
            if real_pkg != package_name:
                logger.info(f"📌 系统实际包名: {real_pkg} (静态解析: {package_name})，采用系统包名")
                package_name = real_pkg
            else:
                logger.info(f"✅ 静态解析包名与系统安装结果一致: {package_name}")
            # 查询系统认定的真实launcher activity(优于静态解析)
            real_activity = adb.get_launcher_activity(package_name)
            if real_activity:
                if real_activity != main_activity:
                    logger.info(f"📌 系统实际launcher: {real_activity} (静态解析: {main_activity})，采用系统结果")
                else:
                    logger.info(f"✅ launcher activity与系统一致: {main_activity}")
                main_activity = real_activity
        else:
            logger.info(f"   差集验证未确定，沿用静态解析包名: {package_name}")

        # 使用adb尝试关闭安全弹窗
        logger.info("   检查并关闭安装后的安全弹窗...")
        _close_security_dialogs_adb(adb)
    
    # 连接uiautomator2
    logger.info("\n" + "=" * 60)
    logger.info("🔌 连接uiautomator2")
    logger.info("=" * 60)
    
    try:
        device = u2.connect(adb.device_id)
        logger.info(f"✅ uiautomator2已连接")
        
        info = device.device_info
        logger.info(f"   设备: {info.get('brand', 'N/A')} {info.get('model', 'N/A')}")
        logger.info(f"   Android: {info.get('version', 'N/A')}")
        
        # 将device对象传给PCAPdroid控制器
        pcapdroid.device = device
        
        # 再次处理可能存在的安全弹窗（使用uiautomator2）
        _close_security_dialogs_ui(device)
        
    except Exception as e:
        logger.error(f"❌ uiautomator2连接失败: {e}")
        return
    
    # 启动PCAPdroid抓包
    logger.info("\n" + "=" * 60)
    logger.info("📡 启动PCAPdroid抓包")
    logger.info("=" * 60)
    
    if not pcapdroid.start_capture(package_name):
        logger.error("❌ 启动抓包失败")
        return
    
    # 启动应用
    logger.info("\n" + "=" * 60)
    logger.info("🚀 启动应用")
    logger.info("=" * 60)
    
    launcher = AppLauncher(adb)
    if not launcher.launch_app(package_name, main_activity, device):
        logger.error("❌ 应用启动失败")
        pcapdroid.stop_capture()
        return
    
    # 等待应用启动并处理可能的安全弹窗
    # 权限/隐私等弹窗可能分多次出现，处理两轮以确保能正常进入首页
    time.sleep(2)
    logger.info("   检查应用启动后的安全弹窗（第1轮）...")
    _close_security_dialogs_ui(device)
    time.sleep(2)
    logger.info("   检查应用启动后的安全弹窗（第2轮）...")
    _close_security_dialogs_ui(device)

    # 首页截图（添加异常处理）
    try:
        screenshot_path = screenshots_dir / 'home.png'
        device.screenshot(str(screenshot_path))
        logger.info(f"📸 首页截图: {screenshot_path}")
    except Exception as e:
        logger.warning(f"⚠ 首页截图失败: {e}")

    # 开始自动遍历或反复启停运行
    if args.max_depth > 0:
        traverser = AppTraverser(device, package_name, output_dir)
        traverser.start_traverse(max_depth=args.max_depth)
        traverser.save_log()
    else:
        # 反复启停 + 定时截图流程
        _run_app_with_cycles(
            device, launcher, package_name, main_activity,
            screenshots_dir, args.wait_time,
            args.screenshot_interval, args.restart_count
        )

        # 保存运行日志
        cycle_duration = args.wait_time // (args.restart_count + 1) if (args.restart_count + 1) > 0 else args.wait_time
        traverse_log = {
            'package': package_name,
            'start_time': datetime.now().isoformat(),
            'end_time': datetime.now().isoformat(),
            'max_depth': 0,
            'restart_count': args.restart_count,
            'wait_time': args.wait_time,
            'screenshot_interval': args.screenshot_interval,
            'cycle_duration': cycle_duration,
            'message': f'反复启停{args.restart_count}次，每次运行约{cycle_duration}秒，每{args.screenshot_interval}秒截图一次'
        }

        log_file = output_dir / 'traverse_log.json'
        with open(log_file, 'w', encoding='utf-8') as f:
            json.dump(traverse_log, f, indent=2, ensure_ascii=False)

        logger.info(f"✅ 运行日志已保存: {log_file}")
    
    # 停止抓包并导出
    logger.info("\n" + "=" * 60)
    logger.info("🛑 停止抓包并导出")
    logger.info("=" * 60)
    
    # 停止抓包
    pcapdroid.stop_capture()
    time.sleep(2)
    
    # 导出PCAP文件（通过UI操作）
    pcap_path = pcapdroid.export_pcap()
    
    if not pcap_path:
        # 如果导出失败，直接查找已存在的PCAP文件
        logger.warning("   ⚠ UI导出失败，尝试查找已存在的文件...")
        pcap_path = pcapdroid._find_latest_pcap_file()
    
    if pcap_path:
        # 拉取到本地
        local_pcap = pcapdroid.pull_pcap_to_local(pcap_path, str(output_dir))
    else:
        logger.error("❌ 未找到PCAP文件")
        logger.error("   请检查PCAPdroid是否正常工作")
        local_pcap = None
    
    # 分析PCAP文件生成报告
    if local_pcap and Path(local_pcap).exists():
        logger.info("\n" + "=" * 60)
        logger.info("📊 分析PCAP文件")
        logger.info("=" * 60)
        
        try:
            analyzer = _pcap_analyzer_mod.PCAPAnalyzer(local_pcap)

            if analyzer.load_pcap():
                analyzer.analyze()
                traffic_report = output_dir / f"{Path(local_pcap).stem}_report.json"
                analyzer.generate_report(str(traffic_report))
                
                # 生成完整HTML报告
                logger.info("📊 生成完整HTML报告...")

                html_report = output_dir / f"{dir_name}_complete_report.html"
                
                generator = _report_generator_mod.ReportGenerator()
                generator.load_apk_info(args.apk)
                generator.load_traffic_analysis(str(traffic_report))

                # 提取APK图标(必须)与静态图片资源
                if args.apk:
                    generator.load_apk_images(args.apk)

                if screenshots_dir.exists():
                    generator.load_screenshots(str(screenshots_dir))

                generator.generate_html_report(str(html_report))
                logger.info(f"✅ 完整HTML报告: {html_report}")
                
        except Exception as e:
            logger.warning(f"⚠ PCAP分析失败: {e}")
    
    # 卸载应用
    if args.apk and not args.no_install:
        logger.info("\n" + "=" * 60)
        logger.info("🗑️ 卸载应用")
        logger.info("=" * 60)
        
        try:
            ret, stdout, _ = adb.run_adb(['uninstall', package_name], timeout=30)
            if ret == 0 and 'Success' in stdout:
                logger.info(f"✅ 应用已卸载: {package_name}")
            else:
                logger.warning(f"⚠ 卸载失败: {stdout}")
        except Exception as e:
            logger.warning(f"⚠ 卸载异常: {e}")
    
    # 完成
    print("\n" + "=" * 60)
    print("✅ 任务完成")
    print("=" * 60)
    print(f"📊 输出目录: {output_dir.absolute()}")
    if local_pcap:
        print(f"   📦 PCAP文件: {local_pcap}")
        if 'html_report' in locals() and Path(html_report).exists():
            print(f"   📊 完整报告: {html_report}")
    else:
        print(f"   ❌ PCAP文件未生成")
    print(f"   📝 遍历日志: {output_dir / 'traverse_log.json'}")
    print(f"   📸 截图目录: {output_dir / 'screenshots'}")
    
    print("\n💡 使用浏览器打开HTML报告查看完整分析结果")


if __name__ == '__main__':
    main()

if __name__ == '__main__':
    main()
