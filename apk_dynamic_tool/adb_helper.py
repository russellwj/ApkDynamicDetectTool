#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ADB工具类 - 基础ADB命令封装
"""

import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

import subprocess
import re
from typing import Set, Tuple

class ADBHelper:
    """ADB工具类 - 基础ADB命令封装"""
    
    def __init__(self, device_id: str = None):
        self.device_id = device_id
        self._screen_size = None
    
    def run_adb(self, args: list, timeout: int = 60) -> Tuple[int, str, str]:
        """执行ADB命令"""
        cmd = ['adb']
        if self.device_id:
            cmd.extend(['-s', self.device_id])
        cmd.extend(args)
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                encoding='utf-8',
                errors='ignore'
            )
            return result.returncode, result.stdout.strip(), result.stderr.strip()
        except subprocess.TimeoutExpired:
            return -1, '', 'Timeout'
        except Exception as e:
            return -1, '', str(e)
    
    def check_device(self) -> bool:
        """检查设备连接"""
        ret, stdout, _ = self.run_adb(['devices'])
        if ret != 0:
            logger.error("❌ ADB命令执行失败")
            return False
        
        devices = []
        for line in stdout.split('\n')[1:]:
            if '\tdevice' in line:
                devices.append(line.split('\t')[0])
        
        if not devices:
            logger.error("❌ 未检测到已连接的ADB设备")
            return False
        
        if len(devices) == 1:
            self.device_id = devices[0]
            logger.info(f"✅ 检测到设备: {self.device_id}")
            return True
        else:
            logger.error(f"❌ 检测到多个设备: {devices}，请使用-s指定")
            return False
    
    def get_screen_size(self) -> Tuple[int, int]:
        """获取屏幕尺寸"""
        if self._screen_size:
            return self._screen_size

        ret, stdout, _ = self.run_adb(['shell', 'wm', 'size'])
        if ret == 0:
            match = re.search(r'(\d+)x(\d+)', stdout)
            if match:
                self._screen_size = (int(match.group(1)), int(match.group(2)))
                return self._screen_size

        return (1080, 1920)

    def get_installed_packages(self) -> Set[str]:
        """获取设备当前已安装的包名集合"""
        ret, stdout, _ = self.run_adb(['shell', 'pm', 'list', 'packages'])
        if ret != 0:
            return set()
        packages = set()
        for line in stdout.split('\n'):
            line = line.strip()
            if line.startswith('package:'):
                packages.add(line[len('package:'):])
        return packages

    def detect_installed_package(self, before: Set[str], static_pkg: str = '') -> str:
        """
        对比安装前后的包列表，检测刚安装的真实包名(系统ground truth)

        这是获取混淆APK真实包名最可靠的方式: 系统PackageManager注册的包名，
        优于任何静态解析(androguard/aapt/raw_manifest)。

        Args:
            before: 安装前的包名集合
            static_pkg: 静态解析的包名(多候选时用于择优)

        Returns:
            真实包名; 检测失败(无新包/多包无法确定)返回空字符串
        """
        after = self.get_installed_packages()
        new_pkgs = after - before

        if not new_pkgs:
            logger.debug("   安装前后包列表无差异(可能已存在或安装失败)")
            return ''

        if len(new_pkgs) == 1:
            return new_pkgs.pop()

        # 多个新包: 优先选与静态解析一致的
        if static_pkg and static_pkg in new_pkgs:
            return static_pkg
        # 退而求其次: 选末段与静态包名一致的
        if static_pkg:
            static_last = static_pkg.split('.')[-1]
            for pkg in new_pkgs:
                if pkg.split('.')[-1] == static_last:
                    return pkg
        logger.debug(f"   检测到多个新包无法确定: {new_pkgs}")
        return ''

    def get_launcher_activity(self, package_name: str) -> str:
        """
        通过系统查询应用的真实launcher activity(PackageManager ground truth)

        Args:
            package_name: 包名

        Returns:
            launcher activity完整类名; 查询失败返回空字符串
        """
        ret, stdout, _ = self.run_adb([
            'shell', 'cmd', 'package', 'resolve-activity',
            '--brief', '-c', 'android.intent.category.LAUNCHER', package_name
        ])
        if ret == 0 and stdout:
            # --brief输出格式: "package/activity"，activity可能是相对路径(.Act.X)
            for line in stdout.split('\n'):
                line = line.strip()
                if '/' in line:
                    parts = line.split('/', 1)
                    if len(parts) == 2 and parts[1]:
                        activity = parts[1]
                        # 相对路径形式(.activities.X)转为完整类名，规范且避免下游歧义
                        if activity.startswith('.'):
                            activity = package_name + activity
                        return activity
        return ''


