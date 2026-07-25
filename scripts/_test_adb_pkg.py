#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""验证ADB系统查询方法: get_installed_packages / get_launcher_activity

需真实Android设备(非单测覆盖范围), 直接运行:
    python scripts/_test_adb_pkg.py
"""
import sys
from pathlib import Path

# 把项目根目录加入 sys.path, 使 `import apk_capture_final` 可用
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
import apk_capture_final as ac

adb = ac.ADBHelper()
if not adb.check_device():
    raise SystemExit(1)

# 1. 包列表
pkgs = adb.get_installed_packages()
print(f"\n已安装包数量: {len(pkgs)}")

# 2. launcher activity (用已安装的PCAPdroid测试)
# PCAPdroid包名可能是 com.emanuelef.remote_capture
test_pkgs = ['com.emanuelef.remote_capture', 'com.android.chrome']
for p in test_pkgs:
    if p in pkgs:
        act = adb.get_launcher_activity(p)
        print(f"  {p} -> launcher: {act!r}")
    else:
        print(f"  {p} -> 未安装")

# 3. 模拟差集验证逻辑(演示detect_installed_package的纯逻辑)
before = {'com.a', 'com.b', 'com.emanuelef.remote_capture'}
after = before | {'com.ddtx.dingdatacontact'}
print(f"\n差集逻辑演示:")
print(f"  before={len(before)} after={len(after)} new={after-before}")
print(f"  detect(单新包): {adb.detect_installed_package(before, '')!r}")

before2 = {'com.a'}
after2 = before2 | {'com.gLVNOriR.x', 'com.ddtx.dingdatacontact'}
print(f"  detect(多新包, static=com.ddtx.dingdatacontact): {adb.detect_installed_package(before2, 'com.ddtx.dingdatacontact')!r}")
