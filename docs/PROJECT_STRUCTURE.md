# APK运行时抓包工具 - 项目目录说明

## 目录结构

```
ApkDynamicDetectTool/
├── apk_dynamic_tool/             # 主包: 拆分后的核心实现
│   ├── __init__.py                #   包入口, 重导出主要类与函数
│   ├── adb_helper.py              #   ADBHelper  - ADB命令封装
│   ├── apk_analyzer.py            #   APKAnalyzer - APK静态解析(混淆感知+多方法融合)
│   ├── pcapdroid_controller.py    #   PCAPdroidController - 通过官方Intent API控制抓包
│   ├── app_launcher.py            #   AppLauncher - 精确启动Main Activity
│   ├── app_traverser.py           #   AppTraverser - 深度优先页面遍历
│   ├── dialog_handlers.py         #   模块级辅助: 弹窗处理/周期截图/反复启停
│   ├── pcap_analyzer.py           #   PCAPAnalyzer + IPInfoProvider - Scapy解析PCAP
│   ├── report_generator.py        #   ReportGenerator - 整合HTML报告生成
│   └── capture_pipeline.py        #   main()  - 端到端流程编排
│
├── main/                           # CLI入口脚本(向后兼容)
│   ├── apk_capture_final.py       #   主脚本: APK安装、运行、抓包
│   ├── pcap_analyzer.py           #   PCAP文件分析工具
│   ├── report_generator.py        #   HTML报告生成器
│   └── batch_analyze.py           #   批量分析入口
│
├── tests/                          # 单元测试(unittest) + 测试入口
│   ├── __init__.py
│   ├── run_tests.py                 #   运行入口(支持 --cov 覆盖率报告)
│   ├── _fixtures.py                 #   共享夹具: 合成TLS ClientHello / FakeDevice / fake adb
│   ├── test_adb_helper.py           #   22 测试: ADBHelper(mock subprocess)
│   ├── test_apk_analyzer.py         #   18 测试: APKAnalyzer(混淆检测/候选择优/真实APK)
│   ├── test_pcapdroid_controller.py #   15 测试: Intent参数构造/api_key/pcap查找/VPN
│   ├── test_pcap_analyzer.py        #   39 测试: Scapy合成包验证DNS/HTTP/TLS SNI/报告生成
│   ├── test_report_generator.py     #   30 测试: 聚合/清洗/格式化纯函数+端到端HTML
│   ├── test_app_launcher.py         #   16 测试: AppLauncher与AppTraverser交互逻辑
│   └── test_batch_analyze.py        #   12 测试: 批量入口的工具函数
│
├── scripts/                         # 手工冒烟测试(需真实Android设备, 不在单测覆盖)
│   ├── _test_adb_pkg.py             #   ADB系统查询方法验证
│   ├── _test_diff_min.py            #   最小化差集诊断
│   └── _test_install_diff.py        #   端到端: 安装混淆APK后差集检测真实包名
│
├── docs/                            # 开发与维护文档
│   ├── AGENTS.md                    #   构建与测试说明(供CI/Agent参考)
│   ├── PROJECT_STRUCTURE.md         #   本文件: 目录结构说明
│   └── TOOLS_AND_DEPLOYMENT.md      #   工具原理与部署清单
│
├── config/                          # 配置文件
│   ├── requirements.txt             #   Python运行依赖
│   ├── requirements-dev.txt         #   测试/开发依赖(coverage)
│   └── PCAP.txt                     #   PCAPdroid API Key (运行时读取)
│
├── apk_input/                       # 待分析的APK文件存放目录
│   ├── demo.apk
│   └── ...
│
├── output/                          # 分析结果输出目录
│   └── {APK名}_{时间戳}/
│       ├── capture_*.pcap          #   网络抓包文件
│       ├── capture_*_report.json  #   流量分析JSON
│       ├── capture_*_report.html  #   流量分析HTML
│       ├── *_complete_report.html #   完整HTML报告(APK+截图+流量)
│       ├── traverse_log.json      #   遍历日志
│       └── screenshots/           #   运行时截图
│
├── .gitignore                       # Git忽略规则
├── opencode.json                    # 编辑器配置
└── README.md                        # 项目使用说明(用户面向)
```

## 重构说明

原本 2265 行的 `apk_capture_final.py` 被拆分到 `apk_dynamic_tool/` 包内 7 个职责清晰的模块:
- 每个模块 ~100~600 行, 单一职责
- 模块间通过显式导入协作, 避免隐式全局状态
- 类型注解使用 `TYPE_CHECKING` 防止循环导入

`main/` 目录下的 4 个 `.py` 文件(`apk_capture_final.py` / `pcap_analyzer.py` / `report_generator.py` / `batch_analyze.py`)
保留为**瘦壳shim**, 仅 `from apk_dynamic_tool.X import Y`, 确保:
- `batch_analyze.py` 通过 subprocess 调用 `apk_capture_final.py` 仍可工作
- 旧的 `import apk_capture_final as ac; ac.ADBHelper` 写法兼容
- README 中的 CLI 示例 `python main/apk_capture_final.py -a app.apk` 不变

## 运行测试

详见根目录 [../AGENTS.md](../AGENTS.md) 的"运行测试"小节。简要:

```bash
python tests/run_tests.py -q --cov --cov-html   # 测试 + 覆盖率 + HTML报告
```

## 核心模块职责

### adb_helper.ADBHelper
ADB命令封装: 设备检查/屏幕尺寸/包列表查询/差集检测真实包名/launcher activity查询。
所有方法基于 `subprocess.run(['adb', ...])` 实现, 易于通过 mock subprocess 测试。

### apk_analyzer.APKAnalyzer
APK静态解析(混淆感知+多方法融合):
- `_extract_from_raw_manifest`: ZIP解压 + UTF-16LE解码 + 正则匹配(对混淆APK最鲁棒)
- `_find_aapt`: 自动查找 aapt.exe(ANDROID_HOME/build-tools)
- `_is_obfuscated_package`: 检测大写字母/随机字符特征
- `_collect_package_candidates`: 并行收集 androguard / aapt / raw_manifest 三路候选
- `_select_best_candidate`: 按置信度择优(多方法一致 > 非混淆 > raw_manifest兜底)

### pcapdroid_controller.PCAPdroidController
通过 PCAPdroid 官方 CaptureCtrl Activity + Intent API 控制抓包, 无需UI点击:
- `_run_api`: 构造 `am start -e action start/stop -e api_key KEY ...` 命令
- `_read_api_key_from_file`: 从 PCAP.txt 读取API Key(多路径查找)
- `_check_vpn_active`: 通过 ifconfig/ip addr 检测 tun0 VPN隧道
- `_find_latest_pcap_file`: 查找 `/sdcard/Download/PCAPdroid/` 等位置的最新pcap文件
- `_clear_old_pcap_files`: 抓包前清理残留避免误捞

### pcap_analyzer.PCAPAnalyzer + IPInfoProvider
Scapy 离线解析 PCAP:
- `_extract_dns_answer`: 按 rdata Python类型区分 A(IP)/CNAME(域名)/TXT(跳过)
- `_extract_sni`: 字节级解析 TLS ClientHello 提取 SNI 服务器名
- `_analyze_http`: 从 TCP payload 提取明文 HTTP 完整 URL(方法+Host+Path)
- `_analyze_dns` / `_analyze_ip` / `_analyze_tcp` / `_analyze_udp` / `_analyze_tls_sni`
- `IPInfoProvider._identify_cloud_provider`: 基于 org/isp/as 字段识别华为/阿里/腾讯/AWS/运营商

### report_generator.ReportGenerator
整合 APK信息+截图+流量分析生成 HTML 报告:
- `_is_private_ip` / `_is_clean_ip`: 防御性清洗(过滤 `b'xxx.'` 脏字符串)
- `_aggregate_ip_locations` / `_aggregate_time`: 多来源聚合
- `_collect_unified_records`: 以域名为粒度聚合 DNS/HTTP/HTTPS/IP 全量信息
- `_cloud_badge_html_simple`: 云厂商徽章(华为红/阿里腾讯AWS黄/运营商绿)

## 输出目录命名规则

```
output/{APK文件名}_{时间戳}/
```
- APK文件名: 去掉 .apk 后缀, 如 `demo`、`base`
- 时间戳: `YYYYMMDD_HHMMSS`, 如 `20260724_001055`
- 同一APK可多次运行, 每次生成独立的时间戳目录
