#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""最小化差集诊断: 每步打印集合状态

需真实Android设备, 直接运行:
    python scripts/_test_diff_min.py
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
TARGET = 'com.gLVNOriR.WdmKWTgvibRnrKTnFDk'  # 已知真实包名
adb = ac.ADBHelper()
adb.check_device()

# 0. 先清掉残留
print(f"\n[0] 卸载残留 {TARGET}")
adb.run_adb(['uninstall', TARGET], timeout=30)
time.sleep(2)

# 1. before
before = adb.get_installed_packages()
print(f"[1] before: {len(before)}包, 含目标={TARGET in before}")

# 2. install
ret, stdout, _ = adb.run_adb(['install', '-r', APK], timeout=120)
print(f"[2] install: ret={ret} success={'Success' in stdout}")
time.sleep(3)

# 3. after
after = adb.get_installed_packages()
print(f"[3] after: {len(after)}包, 含目标={TARGET in after}")

# 4. 差集
new_pkgs = after - before
print(f"[4] new_pkgs(after-before): {len(new_pkgs)}个 = {new_pkgs}")

# 5. 用detect方法
detected = adb.detect_installed_package(before, '')
print(f"[5] detect返回: {detected!r}")

# 6. 清理
adb.run_adb(['uninstall', TARGET], timeout=30)
print(f"[6] 已清理 {TARGET}")
