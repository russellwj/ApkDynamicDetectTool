#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PCAPdroid控制器 - 通过官方CaptureCtrl API控制抓包,无需UI点击
"""

import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

import time
from pathlib import Path
from typing import Optional, Tuple

try:
    from uiautomator2 import Device
except ImportError:
    Device = None  # type: ignore

from .adb_helper import ADBHelper

class PCAPdroidController:
    """
    PCAPdroid控制器（使用官方API）
    
    通过 CaptureCtrl Activity + Intent 调用PCAPdroid官方API
    API文档: https://github.com/emanuele-f/PCAPdroid/blob/master/docs/app_api.md
    
    核心命令:
      启动: am start -e action start -e api_key KEY -e pcap_dump_mode pcap_file -n com.emanuelef.remote_capture/.activities.CaptureCtrl
      停止: am start -e action stop -e api_key KEY -n com.emanuelef.remote_capture/.activities.CaptureCtrl
      查询: am start -e action get_status -e api_key KEY -n com.emanuelef.remote_capture/.activities.CaptureCtrl
    """
    
    PCAPDROID_PACKAGE = "com.emanuelef.remote_capture"
    CAPTURE_CTRL_ACTIVITY = f"{PCAPDROID_PACKAGE}/.activities.CaptureCtrl"
    
    # PCAP文件存储位置
    PCAP_LOCATIONS = [
        '/sdcard/Download/PCAPdroid',
        '/sdcard/PCAPdroid',
        '/storage/emulated/0/Download/PCAPdroid',
        '/storage/emulated/0/PCAPdroid',
    ]
    
    def __init__(self, adb: "ADBHelper", device: "Device" = None, api_key: str = None):
        self.adb = adb
        self.device = device
        self.is_capturing = False
        self.pcap_name = None  # 当前抓包的PCAP文件名
        
        # API Key：如果未传入，尝试从PCAP.txt文件读取
        if api_key:
            self.api_key = api_key
        else:
            self.api_key = self._read_api_key_from_file()
        
        # 尝试永久关闭安全弹窗（荣耀/华为设备）
        self._disable_security_notifications()
        
        logger.info(f"   🔑 API Key: {self.api_key[:8]}..." if len(self.api_key) > 8 else f"   🔑 API Key: {self.api_key}")
    
    def _read_api_key_from_file(self) -> str:
        """从PCAP.txt文件读取API Key"""
        possible_paths = [
            Path('PCAP.txt'),
            Path('pcap.txt'),
            Path('config/PCAP.txt'),
            Path('config/pcap.txt'),
            Path(__file__).parent / 'PCAP.txt',
            Path(__file__).parent / 'pcap.txt',
        ]
        
        for path in possible_paths:
            if path.exists():
                try:
                    key = path.read_text(encoding='utf-8').strip()
                    if key:
                        logger.info(f"   📂 从 {path.name} 读取API Key")
                        return key
                except Exception as e:
                    logger.warning(f"   ⚠ 读取 {path} 失败: {e}")
        
        logger.warning("   ⚠ 未找到PCAP.txt，API Key为空（会弹出权限弹窗）")
        return ""
    
    def _disable_security_notifications(self):
        """尝试永久关闭安全弹窗通知（荣耀/华为设备）"""
        try:
            disable_commands = [
                ['shell', 'settings', 'put', 'global', 'package_verifier_enable', '0'],
                ['shell', 'settings', 'put', 'global', 'package_verifier_user_consent', '0'],
                ['shell', 'settings', 'put', 'secure', 'install_non_market_apps', '1'],
                ['shell', 'settings', 'put', 'global', 'adb_enabled', '1'],
                ['shell', 'settings', 'put', 'secure', 'huawei_install_non_market_apps', '1'],
            ]
            for cmd in disable_commands:
                try:
                    self.adb.run_adb(cmd, timeout=5)
                except:
                    pass
            logger.info("   ✅ 已尝试关闭安全弹窗通知（需设备支持）")
        except Exception as e:
            logger.warning(f"   ⚠ 关闭安全弹窗通知失败: {e}")
    
    def _run_api(self, action: str, extra_params: dict = None) -> Tuple[int, str, str]:
        """
        调用PCAPdroid官方API
        
        Args:
            action: start / stop / get_status
            extra_params: 额外Intent参数
        
        Returns:
            (return_code, stdout, stderr)
        """
        cmd = ['shell', 'am', 'start']
        cmd.extend(['-e', 'action', action])
        cmd.extend(['-e', 'api_key', self.api_key])
        
        if extra_params:
            for key, value in extra_params.items():
                cmd.extend(['-e', key, str(value)])
        
        cmd.extend(['-n', self.CAPTURE_CTRL_ACTIVITY])
        
        logger.debug(f"   API命令: {' '.join(cmd)}")
        return self.adb.run_adb(cmd, timeout=15)
    
    def check_installation(self) -> bool:
        """检查PCAPdroid是否已安装"""
        ret, stdout, _ = self.adb.run_adb([
            'shell', 'pm', 'list', 'packages', self.PCAPDROID_PACKAGE
        ])
        
        if self.PCAPDROID_PACKAGE in stdout:
            logger.info("✅ PCAPdroid已安装")
            return True
        
        logger.error("❌ PCAPdroid未安装")
        return False
    
    def start_capture(self, target_package: str = None) -> bool:
        """
        启动PCAPdroid抓包（纯API方式，无需UI点击）
        
        通过PCAPdroid官方API（CaptureCtrl Activity + Intent）启动抓包。
        传入api_key后，PCAPdroid不会弹出权限确认弹窗，直接开始抓包。
        抓包在后台通过VPN隧道运行，不需要PCAPdroid在前台。
        
        Args:
            target_package: 目标应用包名（可选，用于app_filter）
            
        Returns:
            是否启动成功
        """
        logger.info("📡 启动PCAPdroid抓包（纯API，无UI操作）...")

        if self.is_capturing:
            logger.info("   已在抓包状态")
            return True

        try:
            # 0. 清理上次运行残留的PCAP文件，避免本次崩溃时误捞旧文件张冠李戴
            self._clear_old_pcap_files()

            # 1. 构建API参数
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            self.pcap_name = f"capture_{timestamp}"
            
            extra_params = {
                'pcap_dump_mode': 'pcap_file',
                'pcap_name': self.pcap_name,
            }
            
            if target_package:
                extra_params['app_filter'] = target_package
                logger.info(f"   🎯 应用过滤: {target_package}")
            else:
                logger.info("   🌐 全局抓包模式")
            
            logger.info(f"   📁 PCAP文件名: {self.pcap_name}")
            logger.info(f"   🔑 API Key: {self.api_key[:8]}..." if len(self.api_key) > 8 else f"   🔑 API Key: {self.api_key}")
            
            # 2. 调用API启动抓包（核心步骤，无需任何UI操作）
            ret, stdout, stderr = self._run_api('start', extra_params)
            logger.info(f"   📨 API响应: ret={ret}, output={stdout.strip()}")
            
            if ret != 0:
                logger.warning(f"   ⚠ API返回非零: stderr={stderr.strip()}")
            
            # 3. 兜底检查权限弹窗（有API key时通常不会出现）
            time.sleep(1)
            self._handle_pcapdroid_permission_dialog()
            
            # 4. 等待VPN隧道建立（PCAPdroid通过VPN抓包）
            logger.info("   ⏳ 等待VPN隧道建立...")
            vpn_ready = self._wait_for_vpn(timeout=10)
            if vpn_ready:
                logger.info("   ✅ VPN隧道已建立（tun0）")
            else:
                logger.warning("   ⚠ 未检测到VPN隧道，可能仍在建立中...")
            
            # 5. 验证PCAP文件开始写入
            time.sleep(3)
            if self._verify_capture_running():
                self.is_capturing = True
                logger.info("✅ PCAPdroid抓包已启动（后台运行中）")
                return True
            
            # VPN可能还在建立，再等待
            logger.info("   ⏳ 等待更长时间验证...")
            time.sleep(5)
            if self._verify_capture_running():
                self.is_capturing = True
                logger.info("✅ PCAPdroid抓包已启动（延迟确认）")
                return True
            
            # VPN隧道存在但PCAP文件可能还未写入，视为成功
            if vpn_ready or self._check_vpn_active():
                logger.info("✅ VPN隧道活跃，抓包已在后台运行")
                self.is_capturing = True
                return True
            
            logger.warning("   ⚠ 无法完全确认，假设已启动")
            self.is_capturing = True
            return True
                
        except Exception as e:
            logger.error(f"❌ 启动抓包失败: {e}")
            return False
    
    def _handle_pcapdroid_permission_dialog(self):
        """
        处理PCAPdroid权限弹窗（安全兜底）
        
        当API key正确时，PCAPdroid不会弹出权限确认弹窗。
        此方法仅作为安全兜底，处理API key无效或未设置时的权限弹窗。
        
        根据 PCAPdroid API 文档:
        "Since PCAPdroid 1.8.6, you can pass an api_key parameter in the Intent 
         to authenticate the request without showing the permission prompt."
        
        PCAPdroid控制请求弹窗的精确resource-id:
          - 允许按钮: com.emanuelef.remote_capture:id/allow_btn
          - 拒绝按钮: com.emanuelef.remote_capture:id/deny_btn
        """
        if not self.device:
            return
        
        if self.api_key:
            # 有API key时不应该有权限弹窗，快速检查即可
            logger.info("   🔑 已使用API Key，权限弹窗不应出现（快速检查...）")
            
            try:
                time.sleep(1)
                # 优先使用精确resource-id检查
                allow_btn = self.device(resourceId='com.emanuelef.remote_capture:id/allow_btn')
                if allow_btn.exists:
                    logger.warning("   ⚠ 意外弹窗！API Key可能无效，点击'允许'(resource-id)")
                    allow_btn.click()
                    time.sleep(2)
                    return
                
                # 备用：文本匹配
                for keyword in ['允许', 'Allow', '始终允许', 'Grant']:
                    try:
                        btn = self.device(text=keyword, clickable=True)
                        if btn.exists:
                            logger.warning(f"   ⚠ 意外弹窗！API Key可能无效，点击 '{keyword}'")
                            btn.click()
                            time.sleep(2)
                            return
                    except:
                        pass
                logger.info("   ✅ 无权限弹窗（符合预期）")
            except Exception as e:
                logger.debug(f"   弹窗检查失败: {e}")
            return
        
        # 无API key时，需要处理权限弹窗
        logger.info("   ⚠ 无API Key，需要处理权限弹窗...")
        
        max_rounds = 3
        for round_num in range(max_rounds):
            handled = False
            try:
                # 优先使用resource-id
                allow_btn = self.device(resourceId='com.emanuelef.remote_capture:id/allow_btn')
                if allow_btn.exists:
                    logger.info(f"   处理权限弹窗(第{round_num+1}轮): 点击'允许'(resource-id)")
                    allow_btn.click()
                    time.sleep(2)
                    handled = True
                else:
                    # 备用：文本匹配
                    for keyword in ['允许', 'Allow', '始终允许', 'Grant', 'OK', '确定']:
                        try:
                            btn = self.device(text=keyword, clickable=True)
                            if btn.exists:
                                logger.info(f"   处理权限弹窗(第{round_num+1}轮): 点击 '{keyword}'")
                                btn.click()
                                time.sleep(2)
                                handled = True
                                break
                        except:
                            pass
            except Exception as e:
                logger.debug(f"   UI权限处理失败: {e}")
            
            if not handled:
                logger.info("   无权限弹窗" if round_num == 0 else f"   弹窗处理完成({round_num}轮)")
                break
    
    def _wait_for_vpn(self, timeout: int = 10) -> bool:
        """
        等待VPN隧道建立（PCAPdroid通过VPN抓包）
        
        Args:
            timeout: 最大等待时间（秒）
            
        Returns:
            VPN隧道是否已建立
        """
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self._check_vpn_active():
                return True
            time.sleep(1)
        return False
    
    def _check_vpn_active(self) -> bool:
        """
        检查VPN隧道（tun0）是否活跃
        
        PCAPdroid抓包时会建立VPN隧道 tun0，
        这是确认抓包在后台运行的最可靠方式。
        
        Returns:
            VPN隧道是否活跃
        """
        try:
            ret, stdout, _ = self.adb.run_adb(
                ['shell', 'ifconfig', 'tun0'],
                timeout=5
            )
            if ret == 0 and 'UP' in stdout and 'RUNNING' in stdout:
                return True
        except:
            pass
        
        # 备用方法：通过ip命令检查
        try:
            ret, stdout, _ = self.adb.run_adb(
                ['shell', 'ip', 'addr', 'show', 'tun0'],
                timeout=5
            )
            if ret == 0 and 'UP' in stdout:
                return True
        except:
            pass
        
        return False
    
    def _verify_capture_running(self) -> bool:
        """验证抓包是否真的在运行（通过检查PCAP文件是否在写入）"""
        try:
            # 检查PCAP文件是否已创建
            if self.pcap_name:
                for location in self.PCAP_LOCATIONS:
                    expected_path = f"{location}/{self.pcap_name}"
                    ret, size_out, _ = self.adb.run_adb(['shell', 'stat', '-c', '%s', expected_path])
                    if ret == 0 and size_out.strip():
                        try:
                            file_size = int(size_out.strip())
                            if file_size > 0:
                                logger.info(f"   ✅ PCAP文件已创建: {file_size} bytes")
                                return True
                        except ValueError:
                            pass
            
            # 也可以通过API查询状态
            # 但get_status的结果不容易从adb输出中解析
            
            return False
            
        except Exception as e:
            logger.debug(f"   验证抓包状态失败: {e}")
            return False
    
    def stop_capture(self) -> bool:
        """
        停止PCAPdroid抓包（纯API方式，无需UI操作）
        
        Returns:
            是否停止成功
        """
        logger.info("🛑 停止PCAPdroid抓包（纯API，无UI操作）...")
        
        if not self.is_capturing:
            logger.info("   未在抓包状态")
            return True
        
        try:
            # 调用API停止抓包
            ret, stdout, stderr = self._run_api('stop')
            logger.info(f"   📨 API响应: ret={ret}, output={stdout.strip()}")
            
            # 等待VPN隧道断开
            logger.info("   ⏳ 等待VPN隧道断开...")
            for i in range(10):
                if not self._check_vpn_active():
                    logger.info("   ✅ VPN隧道已断开")
                    break
                time.sleep(1)
            else:
                logger.warning("   ⚠ VPN隧道仍在活跃")
            
            # 等待PCAP文件写入完成（PCAPdroid需要时间把缓存刷入文件）
            logger.info("   ⏳ 等待PCAP文件写入完成...")
            time.sleep(3)
            
            self.is_capturing = False
            logger.info("✅ PCAPdroid抓包已停止")
            return True
            
        except Exception as e:
            logger.error(f"❌ 停止抓包失败: {e}")
            self.is_capturing = False
            return False
    
    def _get_status(self) -> bool:
        """
        查询PCAPdroid抓包状态（通过API）
        
        Returns:
            是否正在抓包
        """
        try:
            ret, stdout, stderr = self._run_api('get_status')
            logger.debug(f"   状态查询返回: {stdout.strip()}")
            
            # 检查是否正在运行
            if 'running=true' in stdout.lower():
                return True
            if 'running=false' in stdout.lower():
                return False
            
            # 无法解析，假设正在运行
            return True
            
        except Exception as e:
            logger.warning(f"   查询状态失败: {e}")
            return True
    
    def export_pcap(self) -> Optional[str]:
        """
        导出PCAP文件（API模式下文件自动保存）
        
        使用pcap_file模式时，PCAPdroid会在抓包过程中实时将文件
        保存到 /sdcard/Download/PCAPdroid/ 目录下
        
        Returns:
            手机上的PCAP文件路径
        """
        logger.info("📤 查找PCAP文件...")
        
        try:
            # 优先使用已知的文件名查找
            if self.pcap_name:
                logger.info(f"   查找已知文件: {self.pcap_name}")
                for location in self.PCAP_LOCATIONS:
                    expected_path = f"{location}/{self.pcap_name}"
                    ret, size_out, _ = self.adb.run_adb(['shell', 'stat', '-c', '%s', expected_path])
                    logger.debug(f"   stat {expected_path}: ret={ret}, size={size_out.strip()}")
                    if ret == 0 and size_out.strip():
                        try:
                            file_size = int(size_out.strip())
                            if file_size > 0:
                                logger.info(f"   ✅ 找到PCAP: {expected_path} ({file_size} bytes)")
                                return expected_path
                        except ValueError:
                            pass
            
            # 查找任意最新的PCAP文件
            logger.info("   查找最新PCAP文件...")
            pcap_path = self._find_latest_pcap_file()
            
            if pcap_path:
                logger.info(f"✅ PCAP文件: {pcap_path}")
                return pcap_path
            
            # 没找到，等待再试
            logger.info("   ⏳ 等待PCAP文件生成...")
            time.sleep(3)
            pcap_path = self._find_latest_pcap_file()
            
            if pcap_path:
                logger.info(f"✅ PCAP文件: {pcap_path}")
                return pcap_path
            
            logger.error("❌ 未找到PCAP文件")
            return None
            
        except Exception as e:
            logger.error(f"❌ 导出PCAP文件失败: {e}")
            return self._find_latest_pcap_file()
    
    def _find_latest_pcap_file(self) -> Optional[str]:
        """查找最新的PCAP文件（支持有/无.pcap后缀）"""
        for location in self.PCAP_LOCATIONS:
            try:
                ret, stdout, _ = self.adb.run_adb(['shell', 'ls', '-t', location])
                
                if ret == 0 and stdout:
                    files = stdout.split('\n')
                    for file in files:
                        file = file.strip()
                        if not file:
                            continue
                        # 匹配 .pcap 后缀或以 capture_ 开头的文件
                        if file.endswith('.pcap') or file.startswith('capture_'):
                            full_path = f"{location}/{file}"
                            # 验证文件存在且有内容
                            ret2, size_out, _ = self.adb.run_adb(['shell', 'stat', '-c', '%s', full_path])
                            if ret2 == 0 and size_out.strip():
                                try:
                                    file_size = int(size_out.strip())
                                    if file_size > 0:
                                        logger.info(f"   找到PCAP: {full_path} ({file_size} bytes)")
                                        return full_path
                                except ValueError:
                                    pass
            except Exception:
                continue
        
        return None
    
    def _clear_old_pcap_files(self):
        """清除旧的PCAP文件(每次抓包前调用，避免崩溃时误捞上次残留)"""
        for location in self.PCAP_LOCATIONS:
            try:
                ret, stdout, _ = self.adb.run_adb(['shell', 'ls', location])
                if ret == 0 and stdout:
                    files = stdout.split('\n')
                    for file in files:
                        file = file.strip()
                        if file and (file.endswith('.pcap') or file.startswith('capture_')):
                            self.adb.run_adb(['shell', 'rm', f'{location}/{file}'])
                            logger.info(f"   🧹 清理残留PCAP: {location}/{file}")
            except Exception as e:
                logger.debug(f"   清理 {location} 时异常: {e}")
    
    def pull_pcap_to_local(self, remote_path: str, local_dir: str) -> Optional[str]:
        """
        拉取PCAP文件到本地
        
        Args:
            remote_path: 手机上的PCAP文件路径
            local_dir: 本地保存目录
        
        Returns:
            本地文件路径
        """
        logger.info(f"📥 拉取PCAP文件到本地...")
        
        try:
            local_dir_path = Path(local_dir)
            local_dir_path.mkdir(parents=True, exist_ok=True)
            
            # 获取远程文件名，确保本地有.pcap后缀
            filename = os.path.basename(remote_path)
            if not filename.endswith('.pcap'):
                filename = filename + '.pcap'
            local_path = local_dir_path / filename
            
            # 拉取文件
            ret, stdout, stderr = self.adb.run_adb([
                'pull', remote_path, str(local_path)
            ], timeout=120)
            
            if ret == 0 and local_path.exists():
                file_size = local_path.stat().st_size
                size_str = f"{file_size / 1024:.1f} KB" if file_size < 1024 * 1024 else f"{file_size / 1024 / 1024:.1f} MB"
                logger.info(f"✅ PCAP文件拉取成功: {local_path}")
                logger.info(f"   文件大小: {size_str} ({file_size} bytes)")
                return str(local_path)
            
            logger.error(f"❌ PCAP文件拉取失败: {stderr}")
            return None
            
        except Exception as e:
            logger.error(f"❌ 拉取PCAP文件失败: {e}")
            return None


