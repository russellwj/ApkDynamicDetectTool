#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端到端验证: 安装混淆APK后差集检测真实包名 + launcher activity

需真实Android设备, 直接运行:
    python scripts/_test_install_diff.py
"""
import sys
from pathlib import Path

# 把项目根目录加入 sys.path, 使 `import apk_capture_final` 可用
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
import time
import apk_capture_final as ac

# 相对项目根目录的APK路径
APK = str(Path(__file__).resolve().parent.parent / 'apk_input' / 'AM.apk')
adb = ac.ADBHelper()
if not adb.check_device():
    raise SystemExit(1)

# 1. 静态解析(对比用)
print("\n=== 静态解析 ===")
static = ac.APKAnalyzer.get_package_info(APK)
static_pkg = static.get('package', '')
static_act = static.get('activity', '')
print(f"静态包名: {static_pkg}")
print(f"静态activity: {static_act}")

# 2. 安装前包列表
print("\n=== 安装 ===")
before = adb.get_installed_packages()
print(f"安装前包数: {len(before)}")

# 若已存在先卸载(确保差集干净)
if static_pkg in before:
    print(f"  已存在{static_pkg}，先卸载...")
    adb.run_adb(['uninstall', static_pkg], timeout=30)
    time.sleep(2)
    before = adb.get_installed_packages()

ret, stdout, _ = adb.run_adb(['install', '-r', APK], timeout=120)
print(f"安装结果: {'成功' if ret == 0 and 'Success' in stdout else '失败'} {stdout[:60]}")
time.sleep(3)

# 3. 差集检测真实包名
print("\n=== 差集验证(系统ground truth) ===")
real_pkg = adb.detect_installed_package(before, static_pkg)
print(f"系统真实包名: {real_pkg!r}")
if real_pkg and real_pkg != static_pkg:
    print(f"  >>> 静态解析({static_pkg}) != 系统真实({real_pkg})，差集纠正成功!")
elif real_pkg == static_pkg:
    print(f"  >>> 静态与系统一致")

# 4. launcher activity
if real_pkg:
    real_act = adb.get_launcher_activity(real_pkg)
    print(f"系统真实launcher: {real_act!r}")

# 5. 清理: 卸载
print("\n=== 清理 ===")
to_uninstall = real_pkg or static_pkg
ret, stdout, _ = adb.run_adb(['uninstall', to_uninstall], timeout=30)
print(f"卸载 {to_uninstall}: {'成功' if ret == 0 and 'Success' in stdout else '失败'}")
