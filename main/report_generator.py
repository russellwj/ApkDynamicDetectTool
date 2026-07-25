#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
向后兼容入口: 完整HTML报告生成工具

实际实现已迁移到 apk_dynamic_tool.report_generator 模块。
本文件作为顶层 CLI 入口保留。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from apk_dynamic_tool.report_generator import ReportGenerator, main

__all__ = ['ReportGenerator', 'main']


if __name__ == '__main__':
    main()
