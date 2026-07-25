#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK分析器 - 获取包名和启动Activity (混淆感知+多方法融合)
"""

import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

import subprocess
import os
import re
from typing import Dict, Any
from pathlib import Path

try:
    from androguard.core import apk
    HAS_ANDROGUARD = True
except ImportError:
    HAS_ANDROGUARD = False
    logger.warning("⚠ androguard未安装，部分功能可能受限，建议运行: pip install androguard")

# 仅用于类型注解,避免循环导入
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .adb_helper import ADBHelper

class APKAnalyzer:
    """APK分析器 - 获取包名和启动Activity"""
    
    @staticmethod
    def _extract_from_raw_manifest(apk_path: str) -> Dict[str, str]:
        """
        从APK的原始AndroidManifest.xml中提取包名和Activity
        
        适用于androguard/aapt都解析失败的混淆APK（恶意应用常见）
        通过ZIP解压后对二进制XML做正则匹配
        
        策略: 在整个manifest中搜索所有包名模式的字符串，
        统计每个候选包名的"子包数"，子包最多的即为主包名
        """
        info = {'package': '', 'activity': ''}
        
        try:
            import zipfile
            from collections import Counter
            with zipfile.ZipFile(apk_path, 'r') as zf:
                if 'AndroidManifest.xml' not in zf.namelist():
                    return info
                
                manifest_data = zf.read('AndroidManifest.xml')
            
            # 二进制XML中字符串以UTF-16LE编码
            decoded = manifest_data.decode('utf-16le', errors='ignore')
            
            # 匹配所有包名模式: com.xxx.yyy 或 org.xxx.yyy 等
            pkg_pattern = re.compile(
                r'((?:com|org|net|io|cn|info|me|app|dev|android)\.[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)+)'
            )
            
            all_matches = pkg_pattern.findall(decoded)
            if not all_matches:
                return info
            
            # 提取所有候选包名
            candidates = [m[0] for m in all_matches if len(m[0]) > 5]
            
            # 统计每个"根包"的出现次数（子包数）
            # 例如 com.ddtx.dingdatacontact.main -> 根包 com.ddtx.dingdatacontact
            root_counter = Counter()
            for pkg in candidates:
                # 跳过android系统包和已知第三方库
                if pkg.startswith('android.') or pkg.startswith('com.google.'):
                    continue
                if pkg.startswith('com.huawei.') or pkg.startswith('com.xiaomi.'):
                    continue
                if pkg.startswith('com.meizu.') or pkg.startswith('com.oppo.'):
                    continue
                if pkg.startswith('com.netease.') or pkg.startswith('com.amap.'):
                    continue
                
                # 取根包: com.xxx.yyy（三级即可）
                parts = pkg.split('.')
                if len(parts) >= 3:
                    root = '.'.join(parts[:3])
                else:
                    root = pkg
                root_counter[root] += 1
            
            if not root_counter:
                return info
            
            # 出现次数最多的根包即为主包名
            main_pkg = root_counter.most_common(1)[0][0]
            count = root_counter[main_pkg]
            
            # 验证：至少出现2次才可信
            if count >= 2:
                info['package'] = main_pkg
            else:
                # 次数太少，取最长的候选
                long_candidates = [c for c in candidates 
                                   if not c.startswith(('android.', 'com.google.', 'com.huawei.'))]
                if long_candidates:
                    info['package'] = max(long_candidates, key=len)
            
            # 匹配主Activity
            if info['package']:
                # 搜索包含包名的Activity全限定名
                act_pattern = re.compile(
                    rf'({re.escape(info["package"])}(\.[A-Za-z][A-Za-z0-9_]*)+)'
                )
                act_matches = act_pattern.findall(decoded)
                if act_matches:
                    # 优先选择 Splash/Launch/Main Activity
                    activities = [m[0] for m in act_matches]
                    for act in activities:
                        act_lower = act.lower()
                        if any(kw in act_lower for kw in ['splash', 'launch', 'main', 'home', 'entry']):
                            info['activity'] = act
                            break
                    if not info['activity']:
                        info['activity'] = activities[0]
            
            if info['package']:
                logger.info(f"✅ 解析APK成功 (原始Manifest提取)")
                logger.info(f"   包名: {info['package']}")
                if info['activity']:
                    logger.info(f"   主Activity: {info['activity']}")
            
        except Exception as e:
            logger.debug(f"   原始Manifest提取失败: {e}")
        
        return info
    
    @staticmethod
    def _find_aapt() -> str:
        """
        自动查找aapt路径
        
        搜索顺序:
        1. 系统PATH中的aapt
        2. ANDROID_HOME/build-tools/*/aapt.exe
        3. 常见SDK安装路径
        """
        # 方法1: 系统PATH
        try:
            result = subprocess.run(
                ['aapt', 'version'],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0:
                return 'aapt'
        except Exception:
            pass
        
        # 方法2: ANDROID_HOME 环境变量
        android_home = os.environ.get('ANDROID_HOME') or os.environ.get('ANDROID_SDK_ROOT')
        if android_home:
            build_tools = Path(android_home) / 'build-tools'
            if build_tools.exists():
                aapt_files = sorted(build_tools.rglob('aapt.exe'), reverse=True)
                if aapt_files:
                    return str(aapt_files[0])
        
        # 方法3: 常见安装路径
        common_paths = [
            Path(os.path.expanduser('~')) / 'AppData' / 'Local' / 'Android' / 'Sdk',
            Path('C:/Android/Sdk'),
            Path('D:/Android/Sdk'),
        ]
        for sdk_path in common_paths:
            build_tools = sdk_path / 'build-tools'
            if build_tools.exists():
                aapt_files = sorted(build_tools.rglob('aapt.exe'), reverse=True)
                if aapt_files:
                    return str(aapt_files[0])
        
        return ''
    
    @staticmethod
    def _is_obfuscated_package(pkg: str) -> bool:
        """
        检测包名是否被混淆
        
        混淆包名特征:
        - 包含大写字母在非首位（如 com.gLVNOriR.WdmKW...）
        - 段名过短或为随机字符（如 v3ejfn497vo_）
        - 段名不遵循常规命名规则
        """
        if not pkg:
            return False
        
        parts = pkg.split('.')
        for part in parts:
            if not part:
                continue
            # 段名中包含大写字母（正常包名段应全小写）
            if part != part.lower():
                return True
            # 段名过短且包含下划线+数字（混淆特征）
            if len(part) <= 12 and '_' in part and any(c.isdigit() for c in part):
                return True
            # 连续5个以上辅音字母（随机字符特征）
            consonants = re.findall(r'[bcdfghjklmnpqrstvwxyz]{5,}', part.lower())
            if consonants:
                return True
        
        return False
    
    @staticmethod
    def get_package_info(apk_path: str) -> Dict[str, str]:
        """
        从APK文件获取包名和主Activity（混淆感知 + 多方法融合策略）

        策略:
          阶段1 并行收集三路候选: androguard / aapt / 原始Manifest提取
          阶段2 按置信度择优(见 _select_best_candidate):
            ① 非混淆包名 + 多方法一致 → 最高可信
            ② 非混淆包名(单方法) → 优先级 androguard > aapt > raw_manifest
            ③ 全部混淆 → 用原始Manifest(子包数统计法对混淆最鲁棒)
            ④ 全部为空 → 文件名兜底
          阶段3 选择Activity(优先androguard/aapt的main activity)

        Returns:
            {'package': 'com.example.app', 'activity': 'com.example.app.MainActivity'}
        """
        if not os.path.exists(apk_path):
            logger.error(f"❌ APK文件不存在: {apk_path}")
            return {}

        # 阶段1: 收集三路候选
        candidates = APKAnalyzer._collect_package_candidates(apk_path)

        # 阶段2+3: 按置信度选择包名和Activity
        info = APKAnalyzer._select_best_candidate(candidates)

        # 阶段4: 文件名兜底
        if not info['package']:
            info['package'] = os.path.splitext(os.path.basename(apk_path))[0]
            info['source'] = '文件名兜底'
            logger.warning(f"⚠ 无法解析APK，使用文件名作为包名: {info['package']}")

        # 打印最终结果
        logger.info(f"✅ 包名: {info['package']} (来源: {info.get('source', '未知')})")
        if info['activity']:
            logger.info(f"   主Activity: {info['activity']}")
        else:
            logger.warning("⚠ 未获取到主Activity，启动时将用monkey兜底")

        return info

    @staticmethod
    def _collect_package_candidates(apk_path: str) -> Dict[str, Dict]:
        """收集androguard/aapt/原始Manifest三路候选结果"""
        candidates = {
            'androguard': {'package': '', 'activity': ''},
            'aapt': {'package': '', 'activity': ''},
            'raw_manifest': {'package': '', 'activity': ''}
        }

        # 候选1: androguard
        if HAS_ANDROGUARD:
            try:
                a = apk.APK(apk_path)
                pkg = a.get_package()
                act = a.get_main_activity()
                if pkg and pkg != 'None':
                    candidates['androguard']['package'] = pkg
                if act and act != 'None':
                    candidates['androguard']['activity'] = act

                # 附带打印应用信息(仅androguard能拿到)
                APKAnalyzer._log_app_meta(a)

            except Exception as e:
                logger.warning(f"⚠ androguard解析失败: {type(e).__name__}: {str(e)[:80]}")
            else:
                if candidates['androguard']['package']:
                    logger.info(f"   [androguard] 包名: {candidates['androguard']['package']}")
                else:
                    logger.warning("⚠ androguard未获取到包名(可能为混淆APK)")

        # 候选2: aapt
        aapt_path = APKAnalyzer._find_aapt()
        if aapt_path:
            try:
                result = subprocess.run(
                    [aapt_path, 'dump', 'badging', apk_path],
                    capture_output=True, text=True, timeout=30,
                    encoding='utf-8', errors='ignore'
                )
                if result.returncode == 0:
                    pkg_match = re.search(r"package: name='([^']+)'", result.stdout)
                    act_match = re.search(r"launchable-activity: name='([^']+)'", result.stdout)
                    if pkg_match:
                        candidates['aapt']['package'] = pkg_match.group(1)
                    if act_match:
                        candidates['aapt']['activity'] = act_match.group(1)
                    if candidates['aapt']['package']:
                        logger.info(f"   [aapt] 包名: {candidates['aapt']['package']}")
                else:
                    logger.debug(f"   [aapt] 返回非0: {result.stderr[:100]}")
            except FileNotFoundError:
                logger.warning(f"⚠ aapt未找到: {aapt_path}")
            except Exception as e:
                logger.warning(f"⚠ aapt解析失败: {e}")
        else:
            logger.debug("   [aapt] 未找到，跳过")

        # 候选3: 原始Manifest提取(对混淆APK最鲁棒)
        raw_info = APKAnalyzer._extract_from_raw_manifest(apk_path)
        if raw_info.get('package'):
            candidates['raw_manifest']['package'] = raw_info['package']
            candidates['raw_manifest']['activity'] = raw_info.get('activity', '')
            logger.info(f"   [raw_manifest] 包名: {raw_info['package']}")

        return candidates

    @staticmethod
    def _log_app_meta(a):
        """打印androguard提取的应用元信息(应用名/版本/权限数)"""
        try:
            app_name = a.get_app_name()
            if app_name:
                logger.info(f"   应用名: {app_name}")
        except Exception:
            pass
        try:
            vn = a.get_androidversion_name()
            vc = a.get_androidversion_code()
            if vn or vc:
                logger.info(f"   版本: {vn} ({vc})")
        except Exception:
            pass
        try:
            perms = a.get_permissions()
            if perms:
                logger.info(f"   权限数: {len(perms)}")
        except Exception:
            pass

    @staticmethod
    def _select_best_candidate(candidates: Dict[str, Dict]) -> Dict[str, str]:
        """
        按置信度从三路候选中选择最佳包名和Activity

        决策优先级:
          ① 非混淆包名 + 多方法一致 → 最高可信
          ② 非混淆包名(单方法) → 优先级 androguard > aapt > raw_manifest
          ③ 全部混淆 → 用原始Manifest结果(子包数统计法对混淆鲁棒)
          ④ 原始Manifest也空 → 用任意非空混淆结果兜底
        """
        info = {'package': '', 'activity': '', 'source': '', 'all_candidates': []}

        # 收集所有非空包名候选: [(pkg, source, is_obfuscated)]
        pkg_cands = []
        for source in ['androguard', 'aapt', 'raw_manifest']:
            pkg = candidates.get(source, {}).get('package', '')
            if pkg and pkg != 'None':
                pkg_cands.append((pkg, source, APKAnalyzer._is_obfuscated_package(pkg)))

        # 所有候选包名(用于安装前清理残留，确保差集检测干净)
        info['all_candidates'] = [p for p, _, _ in pkg_cands]

        # 非混淆候选
        clean_cands = [(p, s) for p, s, obf in pkg_cands if not obf]
        if clean_cands:
            clean_pkgs = set(p for p, _ in clean_cands)
            if len(clean_pkgs) == 1 and len(clean_cands) >= 2:
                # 多方法一致，最高可信
                info['package'] = clean_cands[0][0]
                info['source'] = "多方法一致(" + "+".join(s for _, s in clean_cands) + ")"
            else:
                # 取优先级最高的非混淆候选
                info['package'] = clean_cands[0][0]
                info['source'] = clean_cands[0][1]
        else:
            # 全部混淆或无候选 → 原始Manifest优先(对混淆鲁棒)
            raw_pkg = candidates.get('raw_manifest', {}).get('package', '')
            if raw_pkg and raw_pkg != 'None':
                info['package'] = raw_pkg
                info['source'] = 'raw_manifest(混淆APK)'
            elif pkg_cands:
                # raw也空，用任意混淆结果兜底
                info['package'] = pkg_cands[0][0]
                info['source'] = f"{pkg_cands[0][1]}(混淆兜底)"

        # 选择Activity: 优先androguard/aapt的main activity，再raw_manifest
        info['activity'] = APKAnalyzer._select_activity(candidates)

        return info

    @staticmethod
    def _select_activity(candidates: Dict[str, Dict]) -> str:
        """
        选择主Activity

        优先级: androguard > aapt > raw_manifest(已优先Splash/Launch/Main)
        都为空则返回空(启动时由monkey兜底)
        """
        for source in ['androguard', 'aapt', 'raw_manifest']:
            act = candidates.get(source, {}).get('activity', '')
            if act and act != 'None':
                return act
        return ''
    
    @staticmethod
    def get_apk_details(apk_path: str) -> Dict[str, Any]:
        """
        获取APK详细信息（可选）
        
        Returns:
            包含应用名称、版本、权限、Activity列表等详细信息
        """
        if not HAS_ANDROGUARD:
            logger.warning("⚠ 需要androguard支持")
            return {}
        
        try:
            a = apk.APK(apk_path)
            
            details = {
                'package': a.get_package(),
                'app_name': a.get_app_name(),
                'version_name': a.get_androidversion_name(),
                'version_code': a.get_androidversion_code(),
                'min_sdk': a.get_min_sdk_version(),
                'target_sdk': a.get_target_sdk_version(),
                'main_activity': a.get_main_activity(),
                'activities': a.get_activities(),
                'permissions': a.get_permissions(),
                'permissions_details': a.get_details_permissions(),
                'libraries': a.get_libraries(),
                'features': a.get_features(),
            }
            
            return details
        except Exception as e:
            logger.error(f"获取APK详细信息失败: {e}")
            return {}
    
    @staticmethod
    def get_launch_activity_from_device(adb: "ADBHelper", package_name: str) -> str:
        """从设备获取应用的启动Activity"""
        # 方法1: 使用cmd package
        ret, stdout, _ = adb.run_adb([
            'shell', 'cmd', 'package', 'resolve-activity',
            '--brief', package_name
        ])
        
        if ret == 0 and stdout:
            match = re.search(rf'{package_name}/([^\s]+)', stdout)
            if match:
                activity = match.group(1)
                logger.info(f"✅ 获取启动Activity: {activity}")
                return activity
        
        # 方法2: 使用dumpsys package
        ret, stdout, _ = adb.run_adb([
            'shell', 'dumpsys', 'package', package_name
        ])
        
        if ret == 0:
            # 查找android.intent.action.MAIN的Activity
            lines = stdout.split('\n')
            for i, line in enumerate(lines):
                if 'android.intent.action.MAIN' in line:
                    # 向上查找Activity声明
                    for j in range(max(0, i-10), i):
                        if package_name in lines[j]:
                            match = re.search(rf'{package_name}/([^\s]+)', lines[j])
                            if match:
                                activity = match.group(1)
                                logger.info(f"✅ 获取启动Activity(dumpsys): {activity}")
                                return activity
        
        logger.warning("⚠ 无法获取启动Activity，使用默认值")
        return f"{package_name}.MainActivity"


