#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
批量APK分析脚本

自动扫描 apk_input/ 目录下的所有APK文件，
逐个调用 apk_capture_final.py 进行安装、抓包、分析、报告生成。

用法:
  python batch_analyze.py
  python batch_analyze.py --max-depth 30
  python batch_analyze.py --wait-time 30
  python batch_analyze.py --skip demo.apk base.apk
"""

import subprocess
import sys
import time
import argparse
import logging
from pathlib import Path
from datetime import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    datefmt='%H:%M:%S'
)
logger = logging.getLogger(__name__)

# 项目路径
PROJECT_DIR = Path(__file__).parent.parent
APK_INPUT_DIR = PROJECT_DIR / 'apk_input'
MAIN_SCRIPT = Path(__file__).parent / 'apk_capture_final.py'


def find_apk_files(input_dir: Path, skip_list: list = None) -> list:
    """
    扫描目录下的所有APK文件
    
    Args:
        input_dir: APK输入目录
        skip_list: 要跳过的APK文件名列表
        
    Returns:
        APK文件路径列表（按文件名排序）
    """
    if not input_dir.exists():
        logger.error(f"❌ APK输入目录不存在: {input_dir}")
        return []
    
    skip_set = set(skip_list) if skip_list else set()
    apk_files = []
    
    for file in sorted(input_dir.iterdir()):
        if file.suffix.lower() == '.apk':
            if file.name in skip_set:
                logger.info(f"   ⏭️ 跳过: {file.name}")
                continue
            apk_files.append(file)
    
    return apk_files


def run_analysis(apk_path: Path, extra_args: list = None) -> tuple:
    """
    调用主脚本分析单个APK
    
    Args:
        apk_path: APK文件路径
        extra_args: 额外命令行参数
        
    Returns:
        (success: bool, duration: float)
    """
    cmd = [sys.executable, str(MAIN_SCRIPT), '-a', str(apk_path)]
    if extra_args:
        cmd.extend(extra_args)
    
    logger.info(f"   命令: {' '.join(cmd)}")
    
    start_time = time.time()
    
    try:
        result = subprocess.run(
            cmd,
            capture_output=False,  # 直接输出到控制台
            text=True,
            timeout=600,  # 单个APK最长10分钟
            cwd=str(PROJECT_DIR)
        )
        duration = time.time() - start_time
        success = result.returncode == 0
        return success, duration
        
    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        logger.error(f"   ⏰ 超时（600秒）")
        return False, duration
        
    except Exception as e:
        duration = time.time() - start_time
        logger.error(f"   ❌ 执行异常: {e}")
        return False, duration


def format_duration(seconds: float) -> str:
    """格式化时长"""
    if seconds < 60:
        return f"{seconds:.0f}秒"
    minutes = int(seconds // 60)
    secs = int(seconds % 60)
    return f"{minutes}分{secs}秒"


def main():
    parser = argparse.ArgumentParser(
        description='批量APK分析脚本 - 逐个分析apk_input目录下的APK文件'
    )
    parser.add_argument(
        '--max-depth', type=int, default=0,
        help='遍历深度，0表示不遍历只等待 (默认: 0)'
    )
    parser.add_argument(
        '--wait-time', type=int, default=30,
        help='应用启动后总运行时间/秒 (默认: 30)'
    )
    parser.add_argument(
        '--screenshot-interval', type=int, default=10,
        help='截图间隔时间/秒 (默认: 10)'
    )
    parser.add_argument(
        '--restart-count', type=int, default=2,
        help='应用反复启停次数，0表示只启动一次不重启 (默认: 2)'
    )
    parser.add_argument(
        '--skip', nargs='*', default=[],
        help='要跳过的APK文件名，如: --skip demo.apk base.apk'
    )
    parser.add_argument(
        '--serial', type=str, default=None,
        help='指定ADB设备序列号'
    )
    parser.add_argument(
        '--clear-data', action='store_true',
        help='安装前清除应用数据'
    )
    
    args = parser.parse_args()
    
    # 构建额外参数
    extra_args = []
    extra_args.extend(['--max-depth', str(args.max_depth)])
    extra_args.extend(['--wait-time', str(args.wait_time)])
    extra_args.extend(['--screenshot-interval', str(args.screenshot_interval)])
    extra_args.extend(['--restart-count', str(args.restart_count)])
    if args.serial:
        extra_args.extend(['-s', args.serial])
    if args.clear_data:
        extra_args.append('--clear-data')

    # 查找APK文件
    logger.info("=" * 60)
    logger.info("📦 批量APK分析")
    logger.info("=" * 60)

    apk_files = find_apk_files(APK_INPUT_DIR, args.skip)

    if not apk_files:
        logger.error("❌ 未找到APK文件")
        return

    total = len(apk_files)
    logger.info(f"   找到 {total} 个APK文件")
    logger.info(f"   输入目录: {APK_INPUT_DIR}")
    logger.info(f"   遍历深度: {args.max_depth}")
    logger.info(f"   总运行时间: {args.wait_time}秒")
    logger.info(f"   截图间隔: {args.screenshot_interval}秒")
    logger.info(f"   反复启停次数: {args.restart_count}")
    logger.info("")
    
    # 逐个分析
    results = []
    start_all = time.time()
    
    for i, apk_path in enumerate(apk_files, 1):
        size_mb = apk_path.stat().st_size / (1024 * 1024)
        
        logger.info("=" * 60)
        logger.info(f"🔍 [{i}/{total}] {apk_path.name} ({size_mb:.1f} MB)")
        logger.info("=" * 60)
        
        success, duration = run_analysis(apk_path, extra_args)
        
        status = "✅ 成功" if success else "❌ 失败"
        logger.info(f"   {status} | 耗时: {format_duration(duration)}")
        logger.info("")
        
        results.append({
            'name': apk_path.name,
            'size_mb': size_mb,
            'success': success,
            'duration': duration,
        })
        
        # 每个APK之间稍作间隔
        if i < total:
            logger.info("   ⏳ 等待5秒后继续下一个...")
            time.sleep(5)
    
    # 汇总报告
    total_duration = time.time() - start_all
    success_count = sum(1 for r in results if r['success'])
    fail_count = total - success_count
    
    logger.info("=" * 60)
    logger.info("📊 批量分析汇总")
    logger.info("=" * 60)
    logger.info(f"   总数: {total}")
    logger.info(f"   成功: {success_count}")
    logger.info(f"   失败: {fail_count}")
    logger.info(f"   总耗时: {format_duration(total_duration)}")
    logger.info("")
    
    # 逐个结果
    logger.info("   序号 | APK文件                    | 大小    | 结果 | 耗时")
    logger.info("   " + "-" * 70)
    for i, r in enumerate(results, 1):
        status = "✅" if r['success'] else "❌"
        logger.info(
            f"   {i:>4} | {r['name']:<26} | {r['size_mb']:>5.1f}MB | {status}  | {format_duration(r['duration'])}"
        )
    
    logger.info("")
    
    # 输出失败的APK列表
    if fail_count > 0:
        logger.info("⚠️ 失败的APK:")
        for r in results:
            if not r['success']:
                logger.info(f"   - {r['name']}")
        logger.info("")
    
    logger.info("=" * 60)
    logger.info("✅ 批量分析完成")
    logger.info("=" * 60)


if __name__ == '__main__':
    main()
