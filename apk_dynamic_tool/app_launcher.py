#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
应用启动器 - 精确启动Main Activity
"""

import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

import time

from .adb_helper import ADBHelper
from .apk_analyzer import APKAnalyzer
from .dialog_handlers import _close_security_dialogs_ui

class AppLauncher:
    """应用启动器 - 精确启动应用的Main Activity"""
    
    def __init__(self, adb: "ADBHelper"):
        self.adb = adb
    
    def launch_app(self, package_name: str, activity: str = None, device=None) -> bool:
        """
        启动应用的Main Activity
        
        Args:
            package_name: 包名
            activity: Activity名称（可选，如果不提供会自动获取）
            device: uiautomator2设备对象（用于检查弹窗）
        
        Returns:
            是否启动成功
        """
        logger.info(f"🚀 启动应用: {package_name}")
        
        # 等待系统反应
        time.sleep(2)
        
        # 检查并关闭弹窗
        if device:
            logger.info("   🔍 检查启动前的系统弹窗...")
            # 使用全局函数处理弹窗
            _close_security_dialogs_ui(device)
            time.sleep(1)
        
        # 先强制停止应用
        self.adb.run_adb(['shell', 'am', 'force-stop', package_name])
        time.sleep(1)
        
        # 如果没有提供Activity，从设备获取
        if not activity:
            activity = APKAnalyzer.get_launch_activity_from_device(self.adb, package_name)
        
        # 使用am start精确启动
        full_component = f"{package_name}/{activity}"
        logger.info(f"   启动组件: {full_component}")
        
        ret, stdout, stderr = self.adb.run_adb([
            'shell', 'am', 'start',
            '-n', full_component,
            '-a', 'android.intent.action.MAIN',
            '-c', 'android.intent.category.LAUNCHER'
        ])
        
        if ret == 0:
            # 检查是否有错误
            if 'Error' in stdout or 'Exception' in stdout:
                logger.error(f"❌ 启动失败: {stdout}")
                return self._fallback_launch(package_name)
            
            logger.info("✅ 应用已启动")
            time.sleep(2)
            return True
        
        logger.error(f"❌ 启动失败: {stderr}")
        return self._fallback_launch(package_name)
    
    def stop_app(self, package_name: str):
        """强制停止应用（用于反复启停流程）"""
        logger.info(f"🛑 停止应用: {package_name}")
        self.adb.run_adb(['shell', 'am', 'force-stop', package_name], timeout=15)
    
    def _fallback_launch(self, package_name: str) -> bool:
        """备用启动方法"""
        logger.info("   ⚠ 尝试备用启动方法...")
        
        # 使用monkey启动
        ret, stdout, _ = self.adb.run_adb([
            'shell', 'monkey', '-p', package_name,
            '-c', 'android.intent.category.LAUNCHER', '1'
        ])
        
        if ret == 0:
            logger.info("✅ 应用已启动(monkey)")
            time.sleep(2)
            return True
        
        logger.error("❌ 备用启动方法失败")
        return False


