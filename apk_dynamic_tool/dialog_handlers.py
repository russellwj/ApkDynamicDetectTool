#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
系统弹窗/权限弹窗处理 + 周期截图 + 反复启停流程编排
"""

import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .adb_helper import ADBHelper
    from .app_launcher import AppLauncher

def _close_security_dialogs_adb(adb: "ADBHelper"):
    """
    使用ADB关闭安全弹窗（荣耀/华为设备 - 精确识别）
    
    常见弹窗类型：
    1. 风险提示弹窗：点击"继续使用"
    2. 移入风险管控中心弹窗：点击"取消"
    
    注意：ADB无法直接输入中文文本，此函数仅做基本处理，
    精确的弹窗处理请使用 _close_security_dialogs_ui
    """
    logger.info("   使用ADB关闭安全弹窗...")
    
    # 按返回键尝试关闭弹窗
    try:
        adb.run_adb(['shell', 'input', 'keyevent', 'KEYCODE_BACK'], timeout=5)
        time.sleep(0.5)
    except:
        pass
    
    logger.info("   ✅ ADB弹窗处理完成")



def _close_security_dialogs_ui(device):
    """
    使用uiautomator2关闭安全弹窗及权限/隐私弹窗
    
    循环处理多个弹窗，直到没有新弹窗出现：
    1. 风险提示弹窗 - 点击"继续使用"
    2. 移入风险管控中心弹窗 - 点击"取消"
    3. 权限请求弹窗 - 点击"允许"/"始终允许"/"仅在使用时允许"
    4. 隐私政策弹窗 - 点击"同意"/"确定"/"我知道了"
    5. 升级提示弹窗 - 点击"以后再说"/"取消"/"暂不"
    """
    logger.info("   使用UI自动化关闭弹窗...")
    
    try:
        time.sleep(1)
        
        max_rounds = 8  # 最多处理8轮弹窗
        
        for round_num in range(max_rounds):
            handled = False
            
            # 1. 风险提示弹窗 - 点击"继续使用"
            for keyword in ['继续使用', '继续安装', '继续', 'Continue']:
                try:
                    btn = device(text=keyword, clickable=True)
                    if btn.exists:
                        logger.info(f"   🛡️ 处理风险提示弹窗: {keyword}")
                        btn.click()
                        time.sleep(1.5)
                        handled = True
                        break
                except:
                    pass
            
            if handled:
                continue
            
            # 2. 移入风险管控中心弹窗 - 点击"取消"
            try:
                risk_text = device(textContains='风险')
                if not risk_text.exists:
                    risk_text = device(textContains='管控')
                if risk_text.exists:
                    cancel_btn = device(text='取消', clickable=True)
                    if cancel_btn.exists:
                        logger.info("   🛡️ 处理风险管控中心弹窗: 取消")
                        cancel_btn.click()
                        time.sleep(1.5)
                        handled = True
                        continue
            except:
                pass
            
            # 3. 权限请求弹窗 - 点击"允许"类按钮
            if not handled:
                for keyword in ['始终允许', '仅在使用时允许', '允许', 'ALLOW', 'Allow']:
                    try:
                        btn = device(text=keyword, clickable=True)
                        if btn.exists:
                            logger.info(f"   🔐 处理权限弹窗: {keyword}")
                            btn.click()
                            time.sleep(1.5)
                            handled = True
                            break
                    except:
                        pass
                
                # 也尝试通过resource-id查找允许按钮
                if not handled:
                    try:
                        # 常见权限弹窗的"允许"按钮
                        for rid in ['com.android.permissioncontroller:id/permission_allow_button',
                                    'android:id/button1',
                                    'com.miui:id/button1']:
                            btn = device(resourceId=rid)
                            if btn.exists:
                                logger.info(f"   🔐 处理权限弹窗(resource-id): {rid}")
                                btn.click()
                                time.sleep(1.5)
                                handled = True
                                break
                    except:
                        pass
            
            if handled:
                continue
            
            # 4. 隐私政策/用户协议弹窗 - 点击"同意"/"确定"
            if not handled:
                for keyword in ['同意并继续', '同意', '确定', '我知道了', '已阅读并同意', 'Agree']:
                    try:
                        btn = device(text=keyword, clickable=True)
                        if btn.exists:
                            logger.info(f"   📜 处理隐私政策弹窗: {keyword}")
                            btn.click()
                            time.sleep(1.5)
                            handled = True
                            break
                    except:
                        pass
            
            if handled:
                continue
            
            # 5. 升级提示/广告弹窗 - 点击"以后再说"/"取消"/"暂不"/"关闭"
            if not handled:
                for keyword in ['以后再说', '暂不', '稍后', '跳过', '关闭', '下次再说']:
                    try:
                        btn = device(text=keyword, clickable=True)
                        if btn.exists:
                            logger.info(f"   ❎ 处理提示弹窗: {keyword}")
                            btn.click()
                            time.sleep(1.5)
                            handled = True
                            break
                    except:
                        pass
            
            # 如果没匹配到特定弹窗，也尝试直接查找"取消"按钮
            if not handled:
                try:
                    cancel_btn = device(text='取消', clickable=True)
                    if cancel_btn.exists:
                        logger.info("   🛡️ 处理取消弹窗: 取消")
                        cancel_btn.click()
                        time.sleep(1.5)
                        handled = True
                        continue
                except:
                    pass
            
            # 没有更多弹窗
            if not handled:
                if round_num == 0:
                    logger.info("   ✅ 无弹窗")
                else:
                    logger.info(f"   ✅ 弹窗处理完成（共{round_num}轮）")
                break
        else:
            logger.info(f"   ✅ 弹窗处理完成（已处理{max_rounds}轮）")
        
    except Exception as e:
        logger.warning(f"   ⚠ UI弹窗处理失败: {e}")



def _take_periodic_screenshots(device, screenshots_dir: Path, total_seconds: int, interval: int, prefix: str = 'run'):
    """
    在指定时长内按间隔截图
    
    Args:
        device: uiautomator2设备对象
        screenshots_dir: 截图保存目录
        total_seconds: 总运行时长（秒）
        interval: 截图间隔（秒）
        prefix: 截图文件名前缀
    """
    elapsed = 0
    shot_idx = 1
    while elapsed < total_seconds:
        # 等待到下一个截图点
        wait = min(interval, total_seconds - elapsed)
        time.sleep(wait)
        elapsed += wait
        
        try:
            shot_name = f'{prefix}_{shot_idx:02d}_{elapsed}s.png'
            shot_path = screenshots_dir / shot_name
            device.screenshot(str(shot_path))
            logger.info(f"📸 截图 #{shot_idx} ({elapsed}s): {shot_name}")
            shot_idx += 1
        except Exception as e:
            logger.warning(f"⚠ 截图 #{shot_idx} 失败: {e}")
            shot_idx += 1



def _run_app_with_cycles(device, launcher: "AppLauncher", package_name: str, main_activity: str,
                         screenshots_dir: Path, wait_time: int,
                         screenshot_interval: int, restart_count: int):
    """
    应用反复启停 + 定时截图流程

    总运行时长 wait_time 秒，分成 (restart_count+1) 个周期，
    每个周期启动应用并按 screenshot_interval 秒间隔截图。
    每次启动后都会处理系统/权限/隐私弹窗，确保能正常进入首页。

    Args:
        device: uiautomator2设备对象
        launcher: AppLauncher实例
        package_name: 包名
        main_activity: 主Activity
        screenshots_dir: 截图保存目录
        wait_time: 总运行时长（秒）
        screenshot_interval: 截图间隔（秒）
        restart_count: 重启次数（0表示只启动一次不重启）
    """
    total_cycles = restart_count + 1  # 启动次数 = 重启次数 + 1
    cycle_duration = wait_time // total_cycles if total_cycles > 0 else wait_time
    # 确保每个周期至少能截一张图
    if cycle_duration < screenshot_interval:
        cycle_duration = screenshot_interval

    logger.info(f"\n🔄 应用运行计划: 共 {total_cycles} 次启动，每次运行 {cycle_duration} 秒")
    logger.info(f"📸 截图间隔: {screenshot_interval} 秒")

    # 第1次运行（应用已由主流程启动）
    logger.info(f"\n▶️ 第 1/{total_cycles} 次运行应用 (持续 {cycle_duration} 秒)...")
    _take_periodic_screenshots(
        device, screenshots_dir,
        total_seconds=cycle_duration,
        interval=screenshot_interval,
        prefix='run_01'
    )

    # 后续重启循环
    for cycle in range(1, total_cycles):
        logger.info(f"\n🔄 第 {cycle}/{restart_count} 次重启应用...")
        launcher.stop_app(package_name)
        time.sleep(2)

        if not launcher.launch_app(package_name, main_activity, device):
            logger.error("❌ 应用重启失败，跳过后续循环")
            break

        # 等待应用启动并处理弹窗，确保进入首页
        # 权限/隐私等弹窗可能分多次出现，处理两轮
        time.sleep(2)
        _close_security_dialogs_ui(device)
        time.sleep(2)
        _close_security_dialogs_ui(device)

        run_prefix = f'run_{cycle+1:02d}'
        logger.info(f"\n▶️ 第 {cycle+1}/{total_cycles} 次运行应用 (持续 {cycle_duration} 秒)...")
        _take_periodic_screenshots(
            device, screenshots_dir,
            total_seconds=cycle_duration,
            interval=screenshot_interval,
            prefix=run_prefix
        )


