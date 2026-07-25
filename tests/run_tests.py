#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
运行全部单元测试的入口脚本, 可选生成覆盖率报告。

用法:
    # 仅运行测试(默认)
    python tests/run_tests.py
    python tests/run_tests.py -q                       # 静默模式
    python tests/run_tests.py -m test_pcap_analyzer    # 仅运行指定模块

    # 测试 + 覆盖率
    python tests/run_tests.py --cov                    # 终端覆盖率
    python tests/run_tests.py --cov --cov-html         # 同时生成HTML报告
    python tests/run_tests.py --cov --cov-min 80       # 覆盖率低于80%则失败

    # 也可作为模块运行
    python -m tests.run_tests --cov --cov-html

退出码:
    0 = 全部通过 (且覆盖率达标, 若设置 --cov-min)
    1 = 有失败/错误, 或覆盖率未达标, 或 coverage 未安装

依赖:
    pip install coverage      # 仅在使用 --cov 时需要
"""

import sys
import warnings
import logging
import argparse
from pathlib import Path
from unittest import TestLoader, TestSuite

# Windows GBK 控制台无法打印 emoji/中文, 统一重配 stdout/stderr 为 UTF-8
for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding='utf-8', errors='replace')  # type: ignore[attr-defined]
    except Exception:
        pass  # 旧版 Python 无 reconfigure, 忽略

# 项目根目录(本文件位于 tests/run_tests.py)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
TESTS_DIR = Path(__file__).resolve().parent
COVERAGE_HTML_DIR = PROJECT_ROOT / 'tests' / 'coverage_html'

# 把项目根目录加入 sys.path, 使 `import apk_dynamic_tool` 与 `from tests.xxx import ...` 可用
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# 屏蔽 scapy 在 Windows 无 libpcap 时的告警(仅影响实时抓包, 不影响离线 rdpcap)
warnings.filterwarnings('ignore')

# 静默第三方库(androguard/scapy/urllib3)的 DEBUG 日志, 避免刷屏测试输出
# 业务模块的 logging.basicConfig 仍会在自己的 logger 上输出 INFO, 这里只压 root
logging.getLogger().setLevel(logging.WARNING)
for _noisy in ('androguard', 'scapy', 'urllib3'):
    logging.getLogger(_noisy).setLevel(logging.WARNING)


def discover_all() -> TestSuite:
    """发现 tests/ 下所有 test_*.py 模块并组装成 TestSuite"""
    loader = TestLoader()
    return loader.discover(
        start_dir=str(TESTS_DIR),
        pattern='test_*.py',
        top_level_dir=str(PROJECT_ROOT),
    )


def discover_one(module_name: str) -> TestSuite:
    """仅加载单个测试模块, 模块名不带 .py 后缀, 如 test_pcap_analyzer"""
    loader = TestLoader()
    full_name = f'tests.{module_name}' if not module_name.startswith('tests.') else module_name
    return loader.loadTestsFromName(full_name)


def _try_import_coverage():
    """尝试导入 coverage, 失败返回 None 并打印安装提示"""
    try:
        import coverage  # noqa: F401
        return coverage
    except ImportError:
        print(
            '[coverage] 未安装 coverage.py, 无法生成覆盖率报告。\n'
            '         请运行: pip install coverage',
            file=sys.stderr,
        )
        return None


def _build_coverage(coverage_module):
    """构造 Coverage 实例, 测量 apk_dynamic_tool 包(排除 __init__ 重导出)"""
    cov = coverage_module.Coverage(
        source=['apk_dynamic_tool'],
        omit=[
            'apk_dynamic_tool/__init__.py',  # 仅 re-export, 无逻辑
            '*/__pycache__/*',
        ],
        # 顶层 shim 文件不测量(只 from import, 无业务逻辑)
    )
    return cov


def main():
    parser = argparse.ArgumentParser(
        description='运行 ApkDynamicDetectTool 的全部单元测试, 可选生成覆盖率报告',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python tests/run_tests.py                            # 全部用例, 详细输出
  python tests/run_tests.py -q                         # 静默(仅显示失败)
  python tests/run_tests.py -m test_pcap_analyzer      # 仅运行指定模块
  python tests/run_tests.py --cov                      # 测试 + 终端覆盖率
  python tests/run_tests.py --cov --cov-html           # 同时生成HTML覆盖率报告
  python tests/run_tests.py --cov --cov-min 80         # 覆盖率<80%视为失败
        """,
    )
    parser.add_argument(
        '-m', '--module', default=None,
        help='仅运行指定模块(如 test_pcap_analyzer 或 tests.test_pcap_analyzer)',
    )
    parser.add_argument(
        '-q', '--quiet', action='store_true',
        help='静默模式, 仅输出失败用例的详细信息',
    )
    parser.add_argument(
        '--no-buffer', action='store_true',
        help='显示测试中的 stdout/stderr(默认屏蔽)',
    )
    parser.add_argument(
        '--cov', action='store_true',
        help='启用代码覆盖率测量(测量 apk_dynamic_tool 包)',
    )
    parser.add_argument(
        '--cov-html', action='store_true',
        help='生成HTML覆盖率报告(写入 tests/coverage_html/), 需配合 --cov',
    )
    parser.add_argument(
        '--cov-min', type=float, default=0.0,
        help='覆盖率最低阈值(百分比, 如 80), 低于此值视为失败; 需配合 --cov',
    )
    args = parser.parse_args()

    # 校验 --cov-html / --cov-min 必须配合 --cov
    if (args.cov_html or args.cov_min > 0) and not args.cov:
        parser.error('--cov-html / --cov-min 必须与 --cov 一起使用')

    # 启动 coverage (在导入被测代码之前)
    cov = None
    if args.cov:
        coverage_module = _try_import_coverage()
        if coverage_module is None:
            return 1
        cov = _build_coverage(coverage_module)
        cov.start()

    try:
        # 组装测试集(此处会触发 apk_dynamic_tool 与 tests.* 的导入, 已在 coverage 测量之下)
        if args.module:
            try:
                suite = discover_one(args.module)
            except (ImportError, ModuleNotFoundError) as e:
                print(f'[error] 无法加载测试模块 {args.module}: {e}', file=sys.stderr)
                return 1
        else:
            suite = discover_all()

        # 运行测试(也处于 coverage 测量之下, 故方法体执行会被记录)
        import unittest
        verbosity = 0 if args.quiet else 2
        runner = unittest.TextTestRunner(
            verbosity=verbosity,
            buffer=not args.no_buffer,
        )
        result = runner.run(suite)
    finally:
        # 无论测试是否抛异常, 都停止 coverage 并保存数据
        if cov is not None:
            cov.stop()
            cov.save()

    # 测试结果汇总
    print('\n' + '=' * 60)
    print('Test Summary')
    print('=' * 60)
    print(f'  run:      {result.testsRun}')
    print(f'  failures: {len(result.failures)}')
    print(f'  errors:   {len(result.errors)}')
    print(f'  skipped:  {len(result.skipped)}')
    test_ok = result.wasSuccessful()
    status = 'PASS (all green)' if test_ok else 'FAIL (see above)'
    print(f'  status:   {status}')
    print('=' * 60)

    # 覆盖率报告
    cov_ok = True
    cov_pct = 0.0
    if cov is not None:
        print('\n' + '=' * 60)
        print('Coverage Summary')
        print('=' * 60)
        # 终端报告(返回总覆盖率百分比)
        cov_pct = cov.report(show_missing=True)
        if args.cov_html:
            cov.html_report(directory=str(COVERAGE_HTML_DIR))
            print(f'\nHTML report: {COVERAGE_HTML_DIR / "index.html"}')
        print('=' * 60)
        if args.cov_min > 0:
            if cov_pct < args.cov_min:
                cov_ok = False
                print(f'  coverage {cov_pct:.2f}% < required {args.cov_min:.2f}%  -> FAIL')
            else:
                print(f'  coverage {cov_pct:.2f}% >= required {args.cov_min:.2f}%  -> PASS')
        else:
            print(f'  total coverage: {cov_pct:.2f}%')

    # 综合退出码: 测试失败 OR 覆盖率不达标 都返回1
    return 0 if (test_ok and cov_ok) else 1


if __name__ == '__main__':
    sys.exit(main())
