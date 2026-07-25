#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
向后兼容入口: APK安装、自动遍历与运行时抓包脚本 (完整自动化版)

实际实现已迁移到 apk_dynamic_tool 包:
  - adb_helper.ADBHelper
  - apk_analyzer.APKAnalyzer
  - pcapdroid_controller.PCAPdroidController
  - app_launcher.AppLauncher
  - app_traverser.AppTraverser
  - dialog_handlers (_close_security_dialogs_adb/_close_security_dialogs_ui/
                     _take_periodic_screenshots/_run_app_with_cycles)
  - capture_pipeline.main  (CLI入口)

本文件作为顶层入口保留, 供 batch_analyze.py / _test_*.py / README 示例继续使用。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

# 1) 重新导出主要类/函数 (供 `import apk_capture_final as ac; ac.ADBHelper` 使用)
from apk_dynamic_tool.adb_helper import ADBHelper
from apk_dynamic_tool.apk_analyzer import APKAnalyzer
from apk_dynamic_tool.pcapdroid_controller import PCAPdroidController
from apk_dynamic_tool.app_launcher import AppLauncher
from apk_dynamic_tool.app_traverser import AppTraverser
from apk_dynamic_tool.dialog_handlers import (
    _close_security_dialogs_adb,
    _close_security_dialogs_ui,
    _take_periodic_screenshots,
    _run_app_with_cycles,
)
from apk_dynamic_tool.pcap_analyzer import PCAPAnalyzer, IPInfoProvider
from apk_dynamic_tool.report_generator import ReportGenerator

# 2) 运行时依赖检测 (与原脚本行为一致)
try:
    import uiautomator2 as u2  # noqa: F401
    from uiautomator2 import Device  # noqa: F401
    HAS_UI2 = True
except ImportError:
    HAS_UI2 = False

try:
    from androguard.core import apk  # noqa: F401
    HAS_ANDROGUARD = True
except ImportError:
    HAS_ANDROGUARD = False


def main():
    """CLI入口, 委托给 apk_dynamic_tool.capture_pipeline.main"""
    from apk_dynamic_tool.capture_pipeline import main as _main
    _main()


if __name__ == '__main__':
    main()
