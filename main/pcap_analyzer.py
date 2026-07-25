#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
向后兼容入口: PCAP文件解析和报告生成工具

实际实现已迁移到 apk_dynamic_tool.pcap_analyzer 模块。
本文件作为顶层 CLI 入口保留, 供 README 示例与外部脚本继续使用。
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from apk_dynamic_tool.pcap_analyzer import (
    PCAPAnalyzer,
    IPInfoProvider,
    HAS_SCAPY,
    main,
)

__all__ = ['PCAPAnalyzer', 'IPInfoProvider', 'HAS_SCAPY', 'main']


if __name__ == '__main__':
    main()
