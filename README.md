# APK安全分析工具套件

自动化的APK安装、运行、网络抓包和流量分析工具

## 📁 目录结构

```
ApkDynamicDetectTool/
├── apk_dynamic_tool/             # 主包: 拆分后的核心实现
│   ├── __init__.py
│   ├── adb_helper.py
│   ├── apk_analyzer.py
│   ├── apk_downloader.py
│   ├── chrome_monitor.py          # Chrome CDP 监控: 捕获APK下载链接
│   ├── pcapdroid_controller.py
│   ├── app_launcher.py
│   ├── app_traverser.py
│   ├── dialog_handlers.py
│   ├── pcap_analyzer.py
│   ├── report_generator.py
│   └── capture_pipeline.py
├── main/                          # CLI入口脚本(向后兼容)
│   ├── apk_capture_final.py      # 主脚本: APK安装、运行、抓包
│   ├── pcap_analyzer.py          # PCAP文件分析工具
│   ├── report_generator.py       # HTML报告生成器
│   └── batch_analyze.py          # 批量分析入口
├── tests/                        # 单元测试
├── scripts/                      # 手工冒烟测试(需真实设备)
├── docs/                         # 项目文档
├── config/                       # 配置文件
│   ├── requirements.txt
│   ├── requirements-dev.txt
│   └── PCAP.txt                  # PCAPdroid API Key
├── apk_input/                    # 待分析的APK文件
└── output/                       # 分析结果输出
```

## 🚀 快速开始

### 1. 安装依赖

```bash
pip install -r config/requirements.txt
```

依赖包：
- `uiautomator2>=3.0.0` - Android UI自动化框架
- `androguard>=3.4.0` - APK文件解析库
- `scapy>=2.5.0` - PCAP文件分析库

### 2. 准备环境

**设备要求**：
- Android手机已连接并开启USB调试
- PCAPdroid应用已安装（推荐v1.9.1+）

**检查设备连接**：
```bash
adb devices
```

### 3. 运行分析

**基本用法（默认等待15秒）**：
```bash
python main/apk_capture_final.py -a your_app.apk
```

**完整工作流程**：
1. 解析APK信息（包名、主Activity等）
2. 安装APK到设备
3. 启动PCAPdroid开始抓包
4. 启动目标应用
5. 等待指定时间（默认15秒）
6. 停止抓包并导出PCAP文件
7. 分析PCAP文件提取流量信息
8. 生成完整HTML报告
9. **自动卸载应用**（保持设备清洁）

## ⚙️ 参数说明

### apk_capture_final.py

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-a, --apk` | APK文件路径（必需） | - |
| `--url` | APK下载URL，下载后自动检测（与-a/--monitor互斥） | - |
| `--monitor` | 启动Chrome监控模式，捕获APK下载链接（与-a/--url互斥） | `False` |
| `--monitor-port` | Chrome远程调试端口 | `9222` |
| `--monitor-timeout` | Chrome监控超时秒数 | `300` |
| `-p, --package` | 指定包名（可选） | - |
| `-o, --output` | 输出目录 | `./output` |
| `--max-depth` | 遍历深度，0表示不遍历 | `0` |
| `--wait-time` | 应用启动后等待时间（秒） | `15` |
| `--no-install` | 不安装APK，直接分析已安装应用 | `False` |
| `-s, --serial` | 指定设备序列号 | - |
| `--clear-data` | 安装前清除应用数据 | `False` |

### 使用示例

```bash
# 基本用法（默认等待15秒）
python main/apk_capture_final.py -a app.apk

# 从URL下载APK并分析
python main/apk_capture_final.py --url https://example.com/app.apk

# 批量从URL下载并分析多个APK
python main/batch_analyze.py --url https://a.com/app1.apk https://b.com/app2.apk

# Chrome监控模式（捕获带鉴权的动态下载链接）
# 1. 先启动Chrome: chrome --remote-debugging-port=9222
# 2. 运行工具，在Chrome中登录站点并点击下载
python main/apk_capture_final.py --monitor

# Chrome监控模式（自定义端口和超时）
python main/apk_capture_final.py --monitor --monitor-port 8444 --monitor-timeout 600

# 批量Chrome监控（等待捕获多个APK）
python main/batch_analyze.py --monitor --monitor-count 3

# 等待30秒让应用充分运行
python main/apk_capture_final.py -a app.apk --wait-time 30

# 深度遍历应用界面（遍历20层）
python main/apk_capture_final.py -a app.apk --max-depth 20

# 不安装，分析已安装应用
python main/apk_capture_final.py -p com.example.app --no-install

# 指定输出目录
python main/apk_capture_final.py -a app.apk -o ./my_output

# 多设备时指定设备
python main/apk_capture_final.py -a app.apk -s device_serial_no

# 安装前清除应用数据
python main/apk_capture_final.py -a app.apk --clear-data
```

## 📊 输出文件说明

### 目录命名规则
- **格式**: `{APK文件名}_{时间戳}`
- **示例**: `demo_20260723_221118`
- **优势**: 支持同一应用多次运行，每次生成独立目录

### 1. PCAP文件
- **文件名**: `capture_YYYYMMDD_HHMMSS.pcap`
- **内容**: 完整的网络流量数据包
- **查看**: 使用Wireshark打开分析

### 2. 流量分析报告（JSON）
- **文件名**: `capture_*_report.json`
- **内容**: 
  - DNS解析域名列表
  - IP连接信息
  - TCP/UDP流信息
  - 地理位置和运营商信息

### 3. 流量分析报告（HTML）
- **文件名**: `capture_*_report.html`
- **内容**: 可视化的流量分析结果

### 4. 完整HTML报告
- **文件名**: `{APK文件名}_{时间戳}_complete_report.html`
- **内容**:
  - APK基本信息（包名、版本、大小、MD5等）
  - 运行时截图
  - 网络流量分析结果
  - 统计数据和可视化图表

### 5. 遍历日志
- **文件名**: `traverse_log.json`
- **内容**: 应用界面遍历记录

### 6. 运行截图
- **目录**: `screenshots/`
- **内容**: 应用运行时的界面截图

### 自动清理
- ✅ **应用卸载**: 分析完成后自动卸载应用
- ✅ **保持清洁**: 避免设备上积累测试应用

## 🔍 流量分析工具

### pcap_analyzer.py - 独立分析PCAP文件

```bash
# 分析PCAP文件
python main/pcap_analyzer.py output/应用名/capture_*.pcap

# 指定输出文件
python main/pcap_analyzer.py capture.pcap -o report.json
```

**功能**：
- 提取DNS解析记录
- 统计IP连接信息
- 查询IP地理位置和运营商
- 生成JSON和HTML报告

### report_generator.py - 独立生成完整报告

```bash
# 生成完整HTML报告
python main/report_generator.py app.apk \
  -t output/应用名/capture_*_report.json \
  -s output/应用名/screenshots \
  -o report.html
```

**功能**：
- 整合APK基本信息
- 内嵌运行截图（Base64编码）
- 整合流量分析结果
- 生成美观的HTML报告

## 🛠️ 工作原理

### 1. APK解析
使用`androguard`库解析APK文件：
- 提取包名和主Activity
- 获取应用元数据
- 计算文件哈希值（MD5/SHA256）

### 2. 应用安装
- 通过ADB安装APK
- 处理安装失败和重试

### 3. PCAPdroid抓包
- 使用uiautomator2操作UI启动抓包
- VPN权限自动处理
- 全局抓包模式（更可靠）

### 4. 应用运行
- 精确启动Main Activity
- 等待应用初始化
- 可选深度遍历界面

### 5. 流量导出
- 停止抓包
- 自动查找并拉取PCAP文件
- 验证文件完整性

### 6. 流量分析
- 使用scapy解析PCAP文件
- 提取DNS查询和响应
- 统计TCP/UDP连接
- 查询IP地理位置（ip-api.com免费API）

### 7. 报告生成
- APK基本信息整合
- 截图Base64编码内嵌
- 流量分析结果可视化
- 响应式HTML设计

## 📋 注意事项

### 设备要求
- Android 5.0+（API 21+）
- USB调试已开启
- 已授权ADB调试
- PCAPdroid已安装并运行过一次（完成初始化）

### 网络要求
- IP地理位置查询需要网络连接
- 使用免费API（ip-api.com）有请求限制
- 结果自动缓存，避免重复查询

### 权限要求
- PCAPdroid需要VPN权限
- 应用需要相应权限才能正常运行

### 安全弹窗处理
- ✅ **精确识别**：准确识别风险提示和风险管控中心弹窗
- ✅ **风险提示弹窗**：识别文本并点击"继续使用"
- ✅ **风险管控中心**：识别"风险"/"管控"文本并点击"取消"
- ✅ **处理时机**：仅在APK安装后和启动后处理弹窗
- ✅ **权限弹窗**：自动处理运行时权限请求
- ✅ **多层防护**：ADB方式 + UI自动化双重保障

### PCAPdroid操作保障
- ✅ **步骤验证**：7步启动流程，每步严格验证
- ✅ **前台确认**：操作前确认PCAPdroid在前台
- ✅ **状态验证**：启动前验证未抓包，启动后验证正在抓包
- ✅ **弹窗清除**：每次操作前清除所有弹窗
- ✅ **容错机制**：多种方式尝试，确保操作成功

### 性能建议
- 默认等待15秒可满足大多数应用初始化需求
- 复杂应用可增加等待时间到30-60秒
- 深度遍历会增加运行时间，建议max_depth不超过30
- **多次运行**: 每次运行都会创建新的带时间戳的输出目录
- **自动清理**: 应用在分析完成后自动卸载，避免占用设备空间

## 🐛 故障排查

### ADB设备未连接
```bash
# 检查设备
adb devices

# 重启ADB服务
adb kill-server
adb start-server
```

### PCAP文件未生成
- 确认PCAPdroid已正确安装
- 手动打开PCAPdroid检查是否可以正常抓包
- 检查VPN权限是否已授予

### uiautomator2连接失败
```bash
# 初始化uiautomator2
python -m uiautomator2 init

# 重新连接
python -m uiautomator2 init --serial <device_id>
```

### IP地理位置查询失败
- 检查网络连接
- 等待几分钟后重试（API限制）
- 查看日志中的具体错误信息

## 📝 使用建议

### 基础分析
- 使用默认参数即可（等待15秒）
- 适合快速了解应用的网络行为

### 深度分析
- 增加等待时间到30-60秒
- 或使用max_depth参数遍历应用界面
- 适合全面测试应用功能

### 批量分析
- 逐个应用运行分析
- 避免同时运行多个实例
- 定期清理output目录

### 报告查看
- 使用现代浏览器打开HTML报告
- 建议使用Chrome、Firefox或Edge
- 截图可以放大查看细节

## 📄 许可证

本工具仅供安全研究和测试使用，请遵守相关法律法规。

## 🤝 贡献

欢迎提交Issue和Pull Request！

---

**Made with ❤️ for security researchers**