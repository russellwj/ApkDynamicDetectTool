# AGENTS.md

供 CI / AI agent / 维护者参考的构建与测试说明。

## 环境要求

- Python 3.8+ (开发与测试基于 Python 3.10)
- 操作系统: Windows / Linux / macOS
- 依赖: 见 `config/requirements.txt`
  - `uiautomator2>=3.0.0` (Android UI自动化)
  - `androguard>=3.4.0` (APK静态解析)
  - `scapy>=2.5.0` (PCAP离线解析)

Windows 下 scapy 会输出 `WARNING: No libpcap provider available`, 这是
实时抓包功能缺失的告警, 不影响离线 `rdpcap()` 读 PCAP 文件, 测试不受影响。

## 安装依赖

```bash
pip install -r config/requirements.txt
```

## 项目结构

详见 [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)。

核心代码在 `apk_dynamic_tool/` 包内, `main/` 目录下的 `apk_capture_final.py` /
`pcap_analyzer.py` / `report_generator.py` 是向后兼容的瘦壳shim,
`batch_analyze.py` 是批量入口(通过 subprocess 调用主入口)。

## 运行测试

推荐使用 `tests/run_tests.py` 入口(支持覆盖率报告):

```bash
# 全部测试(默认详细输出)
python tests/run_tests.py

# 静默模式(仅显示失败用例)
python tests/run_tests.py -q

# 仅运行指定模块
python tests/run_tests.py -m test_pcap_analyzer

# 测试 + 终端覆盖率报告
python tests/run_tests.py --cov

# 测试 + 终端覆盖率 + HTML报告(写入 tests/coverage_html/index.html)
python tests/run_tests.py --cov --cov-html

# 设置最低覆盖率阈值(低于则返回非0退出码, 适合CI)
python tests/run_tests.py --cov --cov-min 80

# 也可作为模块运行
python -m tests.run_tests --cov --cov-html
```

兼容原有的 unittest 命令:

```bash
python -m unittest discover -s tests -v                    # 全部
python -m unittest tests.test_pcap_analyzer -v            # 单模块
python -m unittest tests.test_pcap_analyzer.TestExtractSni.test_valid_sni -v   # 单用例
```

测试统计:
- 238 个用例, 8 个测试模块, 1 个共享夹具模块
- 全部通过耗时 < 40 秒(已 patch `time.sleep`)
- 当前覆盖率 48%(其余代码需真实Android设备, 不在单测覆盖)

依赖: 使用 `--cov` 需额外安装 `pip install -r config/requirements-dev.txt`(含 coverage>=7.0)

## 测试覆盖范围

| 测试模块 | 覆盖目标 | 测试数 |
|----------|----------|--------|
| test_adb_helper | ADBHelper(mock subprocess): run_adb/check_device/get_screen_size/get_installed_packages/detect_installed_package/get_launcher_activity | 22 |
| test_apk_analyzer | APKAnalyzer: _is_obfuscated_package/_select_best_candidate/_select_activity/_extract_from_raw_manifest/get_package_info(真实demo.apk)/_find_aapt | 18 |
| test_apk_downloader | ApkDownloader: _validate_url/_infer_filename/_validate_apk/download(成功/失败/批量)/capture_pipeline+batch_analyze集成 | 30 |
| test_chrome_monitor | ChromeMonitor: _is_apk_request/CapturedTarget/_discover_targets/CDP连接/事件解析/wait_for_apk(s)/ApkDownloader headers/pipeline集成 | 56 |
| test_pcapdroid_controller | PCAPdroidController: _run_api命令构造/check_installation/_read_api_key_from_file/_find_latest_pcap_file/_check_vpn_active/_clear_old_pcap_files | 15 |
| test_pcap_analyzer | PCAPAnalyzer + IPInfoProvider: _extract_dns_answer/_extract_sni/_analyze_dns/_analyze_http/_analyze_tls_sni/_analyze_ip/_analyze_tcp/_analyze_udp/全流程load+analyze+generate_report/IPInfoProvider云厂商识别 | 39 |
| test_report_generator | ReportGenerator: _is_private_ip/_is_clean_ip/_cloud_badge_html_simple/_aggregate_ip_locations/_aggregate_time/_collect_unified_records/_format_url_cell/端到端HTML生成 | 30 |
| test_app_launcher | AppLauncher(am start + monkey兜底)/AppTraverser(should_skip_element/get_element_signature/handle_permission_dialogs/save_log) | 16 |
| test_batch_analyze | batch_analyze: find_apk_files/format_duration/run_analysis(mock subprocess) | 12 |

## 不在单测覆盖范围(需真实设备/网络)

以下场景需通过真实Android设备端到端验证, 不在unittest覆盖中:
- `capture_pipeline.main()` 全流程编排(需ADB设备+PCAPdroid+uiautomator2)
- `ADBHelper.check_device()` 真实设备连接
- `PCAPdroidController.start_capture()/stop_capture()` 真实抓包启停
- `IPInfoProvider.get_ip_info()` 真实 ip-api.com 网络调用(已 mock)
- `AppTraverser.traverse_page()` 真实UI遍历

旧的手工冒烟测试脚本(需真实设备, 已迁移到 scripts/):
- `scripts/_test_adb_pkg.py` / `scripts/_test_diff_min.py` / `scripts/_test_install_diff.py`

## CLI 入口(向后兼容)

```bash
# 主入口: 全流程
python main/apk_capture_final.py -a app.apk
python main/apk_capture_final.py -a app.apk --max-depth 30
python main/apk_capture_final.py -p com.example.app --no-install
python main/apk_capture_final.py --url https://example.com/app.apk
python main/apk_capture_final.py --monitor  # Chrome监控模式

# 单独分析PCAP
python main/pcap_analyzer.py capture.pcap -o report.json

# 单独生成报告
python main/report_generator.py app.apk -t report.json -s screenshots/

# 批量分析
python main/batch_analyze.py
```

## 维护约定

- 修改核心实现: 编辑 `apk_dynamic_tool/` 下的对应模块, **不要**改 `main/` 下的 shim
- 添加新功能: 在 `apk_dynamic_tool/` 下新建模块, 在 `__init__.py` 添加 re-export
- 修改后必跑: `python -m unittest discover -s tests`
- 新增类/函数: 同步补 `tests/test_*.py`, 保持测试覆盖率不下降
- 不要在源码中添加新注释(项目约定: 不写注释, 命名自解释)
- 提交前确认: `python -m unittest discover -s tests` 通过且无新增 warning
