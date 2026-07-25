#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
应用页面自动遍历器 - 深度优先遍历,自动点击/滚动/截图
"""

import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

import time
import json
from datetime import datetime
from pathlib import Path
from typing import List, Set, Dict
import logging

try:
    from uiautomator2 import Device
except ImportError:
    Device = None  # type: ignore

class AppTraverser:
    """
    应用页面自动遍历器
    深度优先遍历应用所有页面，自动点击、滚动
    """
    
    def __init__(self, device: Device, package_name: str, output_dir: Path):
        self.device = device
        self.package_name = package_name
        self.output_dir = output_dir
        
        # 确保screenshots目录存在
        self.screenshots_dir = output_dir / 'screenshots'
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        
        # 遍历状态
        self.visited_activities: Set[str] = set()
        self.clicked_elements: Set[str] = set()
        self.traverse_log: List[Dict] = []
        
        self.max_depth = 20
        self.current_depth = 0
        self.max_scroll_times = 3
        self.retry_interval = 3  # 找不到元素时的重试间隔（秒）
        self.max_retry_times = 3  # 最大重试次数
        
        # 权限处理关键词
        self.permission_keywords = [
            '允许', '始终允许', '确定', '同意', '继续',
            'ALLOW', 'OK', 'AGREE', 'CONTINUE', 'ACCEPT'
        ]
        
        # 跳过的元素关键词
        self.skip_keywords = ['设置', '分享', '登录', '注册', '广告', '购买', '支付']
    
    def get_current_app_info(self) -> Dict[str, str]:
        """安全获取当前应用信息"""
        try:
            # uiautomator2中app_current是方法，需要调用
            app_info = self.device.app_current()
            if app_info and isinstance(app_info, dict):
                return {
                    'package': app_info.get('package', ''),
                    'activity': app_info.get('activity', '')
                }
        except Exception as e:
            logger.warning(f"获取当前应用信息失败: {e}")
        
        return {'package': '', 'activity': ''}
    
    def handle_permission_dialogs(self):
        """处理权限弹窗和安全弹窗（荣耀/华为设备 - 精确识别）"""
        try:
            # 1. 处理风险提示弹窗 - 点击"继续使用"
            # 安装后和启动时都会弹出
            for keyword in ['继续使用', '继续安装', '继续', 'Continue']:
                try:
                    elem = self.device(text=keyword, clickable=True)
                    if elem.exists:
                        logger.info(f"   🛡️ 处理风险提示弹窗: {keyword}")
                        elem.click()
                        time.sleep(1)
                        return
                except Exception:
                    pass
            
            # 2. 处理移入风险管控中心弹窗 - 点击"取消"
            try:
                # 查找包含"风险"或"管控"的文本
                risk_text = self.device(textContains='风险') or self.device(textContains='管控')
                if risk_text.exists:
                    # 查找"取消"按钮
                    cancel_btn = self.device(text='取消', clickable=True)
                    if cancel_btn.exists:
                        logger.info("   🛡️ 处理风险管控中心弹窗: 取消")
                        cancel_btn.click()
                        time.sleep(1)
                        return
            except Exception:
                pass
            
            # 3. 处理常见的权限请求弹窗
            for keyword in self.permission_keywords:
                try:
                    elem = self.device(textContains=keyword, clickable=True)
                    if elem.exists:
                        logger.info(f"   🔐 处理权限弹窗: {keyword}")
                        elem.click()
                        time.sleep(0.5)
                        return
                except Exception:
                    pass
            
            # 4. 处理通用的确认类弹窗
            for keyword in ['确认', '确定', 'OK', '是', 'Yes']:
                try:
                    elem = self.device(text=keyword, clickable=True)
                    if elem.exists:
                        logger.info(f"   🔐 处理确认弹窗: {keyword}")
                        elem.click()
                        time.sleep(0.5)
                        return
                except Exception:
                    pass
            
            # 5. 处理取消类弹窗（风险管控中心等）
            for keyword in ['取消', 'Cancel', '暂不', '关闭']:
                try:
                    elem = self.device(text=keyword, clickable=True)
                    if elem.exists:
                        # 检查是否是风险管控中心弹窗
                        parent = elem.sibling(className='*')
                        if parent.exists:
                            parent_text = parent.info.get('text', '')
                            if '风险' in parent_text or '管控' in parent_text or '移入' in parent_text:
                                logger.info(f"   🛡️ 关闭风险管控中心弹窗: {keyword}")
                                elem.click()
                                time.sleep(0.5)
                                return
                except Exception:
                    pass
                    
        except Exception as e:
            logger.warning(f"处理权限弹窗异常: {e}")
    
    def get_clickable_elements(self) -> List[Dict]:
        """获取当前页面的可点击元素"""
        elements = []
        retry_count = 0
        
        while retry_count < self.max_retry_times:
            try:
                # 扫描屏幕上的可点击元素
                for elem in self.device(clickable=True, enabled=True):
                    try:
                        info = elem.info
                        if not info:
                            continue
                        
                        text = info.get('text', '')
                        desc = info.get('contentDescription', '')
                        res_id = info.get('resourceName', '')
                        class_name = info.get('className', '')
                        bounds = info.get('bounds', {})
                        
                        # 过滤无效元素
                        if bounds and bounds.get('right', 0) > bounds.get('left', 0):
                            elements.append({
                                'text': text,
                                'description': desc,
                                'resource_id': res_id,
                                'class': class_name,
                                'bounds': bounds,
                                'center_x': (bounds['left'] + bounds['right']) // 2,
                                'center_y': (bounds['top'] + bounds['bottom']) // 2
                            })
                    except Exception:
                        continue
                
                # 如果找到了元素，直接返回
                if elements:
                    return elements
                
                # 没找到元素，静默等待后重试
                retry_count += 1
                if retry_count < self.max_retry_times:
                    logger.info(f"   ⏳ 未找到可点击元素，等待{self.retry_interval}秒后重试({retry_count}/{self.max_retry_times})")
                    time.sleep(self.retry_interval)
                    
            except Exception as e:
                logger.warning(f"获取元素失败: {e}")
                retry_count += 1
                if retry_count < self.max_retry_times:
                    time.sleep(self.retry_interval)
        
        return elements
    
    def should_skip_element(self, elem_info: Dict) -> bool:
        """判断是否应该跳过该元素"""
        text = elem_info.get('text', '').lower()
        desc = elem_info.get('description', '').lower()
        
        for keyword in self.skip_keywords:
            if keyword.lower() in text or keyword.lower() in desc:
                return True
        
        return False
    
    def get_element_signature(self, elem_info: Dict) -> str:
        """生成元素唯一标识"""
        return f"{elem_info['resource_id']}_{elem_info['class']}_{elem_info['text'][:20]}"
    
    def traverse_page(self, scroll_count: int = 0):
        """递归遍历当前页面"""
        if self.current_depth >= self.max_depth:
            logger.info(f"   ⚠ 达到最大深度 {self.max_depth}")
            return
        
        try:
            # 等待页面稳定
            time.sleep(1)
            
            # 处理权限弹窗
            self.handle_permission_dialogs()
            
            # 检查是否仍在目标应用
            app_info = self.get_current_app_info()
            current_pkg = app_info.get('package', '')
            
            if current_pkg and current_pkg != self.package_name:
                logger.warning(f"   ⚠ 已离开目标应用: {current_pkg}")
                self.device.press('back')
                time.sleep(1)
                return
            
            # 获取当前Activity
            current_activity = app_info.get('activity', '')
            activity_key = f"{current_pkg}/{current_activity}"
            
            # 记录Activity
            if activity_key not in self.visited_activities:
                self.visited_activities.add(activity_key)
                logger.info(f"   ✓ 新页面: {activity_key}")
                
                # 截图（已确保目录存在）
                try:
                    screenshot_path = self.screenshots_dir / f"{len(self.visited_activities)}.png"
                    self.device.screenshot(str(screenshot_path))
                except Exception as e:
                    logger.warning(f"截图失败: {e}")
            else:
                logger.info(f"   ✓ 已访问: {activity_key}")
            
            # 获取可点击元素
            elements = self.get_clickable_elements()
            logger.info(f"   📊 发现 {len(elements)} 个可点击元素")
            
            # 点击元素
            clicked_count = 0
            for elem_info in elements:
                try:
                    if self.current_depth >= self.max_depth:
                        return
                    
                    # 检查是否已点击
                    elem_sig = self.get_element_signature(elem_info)
                    if elem_sig in self.clicked_elements:
                        continue
                    
                    # 检查是否应该跳过
                    if self.should_skip_element(elem_info):
                        continue
                    
                    # 记录点击
                    self.clicked_elements.add(elem_sig)
                    clicked_count += 1
                    
                    elem_text = elem_info.get('text', '') or elem_info.get('description', '') or elem_info.get('resource_id', '') or '未知'
                    logger.info(f"   👆 点击 [{clicked_count}]: {elem_text[:40]}")
                    
                    # 记录日志
                    self.traverse_log.append({
                        'timestamp': datetime.now().isoformat(),
                        'depth': self.current_depth,
                        'action': 'click',
                        'element': elem_text,
                        'activity': activity_key
                    })
                    
                    # 执行点击
                    center_x = elem_info.get('center_x', 0)
                    center_y = elem_info.get('center_y', 0)
                    
                    if center_x > 0 and center_y > 0:
                        self.device.click(center_x, center_y)
                        time.sleep(1.5)
                        
                        # 处理可能的权限弹窗
                        self.handle_permission_dialogs()
                        
                        # 检查页面是否改变
                        new_app_info = self.get_current_app_info()
                        new_pkg = new_app_info.get('package', '')
                        new_activity = new_app_info.get('activity', '')
                        
                        if new_pkg != current_pkg or new_activity != current_activity:
                            # 页面已改变，递归遍历新页面
                            self.current_depth += 1
                            self.traverse_page(scroll_count=0)
                            self.current_depth -= 1
                            
                            # 返回上一页
                            logger.info(f"   ⬅ 返回上一页")
                            self.device.press('back')
                            time.sleep(1)
                            
                except Exception as e:
                    logger.warning(f"   ⚠ 点击失败: {e}")
                    time.sleep(1)
            
            # 滚动页面查找更多元素
            if scroll_count < self.max_scroll_times:
                try:
                    logger.info(f"   📜 滚动页面 ({scroll_count + 1}/{self.max_scroll_times})")
                    
                    width, height = self.device.window_size()
                    self.device.swipe(width // 2, int(height * 0.8), width // 2, int(height * 0.3), 0.3)
                    time.sleep(1)
                    
                    self.traverse_page(scroll_count=scroll_count + 1)
                except Exception as e:
                    logger.warning(f"滚动失败: {e}")
                    
        except Exception as e:
            logger.error(f"遍历页面异常: {e}")
            # 尝试按返回键恢复
            try:
                self.device.press('back')
                time.sleep(1)
            except:
                pass
    
    def start_traverse(self, max_depth: int = 20):
        """开始遍历"""
        logger.info("\n" + "=" * 60)
        logger.info("🚀 开始自动遍历应用")
        logger.info("=" * 60)
        
        self.max_depth = max_depth
        self.traverse_page()
        
        logger.info("\n" + "=" * 60)
        logger.info("✅ 遍历完成")
        logger.info("=" * 60)
        logger.info(f"📊 访问页面数: {len(self.visited_activities)}")
        logger.info(f"📊 点击元素数: {len(self.clicked_elements)}")
    
    def save_log(self):
        """保存遍历日志"""
        log_data = {
            'package_name': self.package_name,
            'visited_activities': list(self.visited_activities),
            'clicked_elements_count': len(self.clicked_elements),
            'traverse_log': self.traverse_log
        }
        
        log_path = self.output_dir / 'traverse_log.json'
        with open(log_path, 'w', encoding='utf-8') as f:
            json.dump(log_data, f, indent=2, ensure_ascii=False)
        
        logger.info(f"✅ 遍历日志已保存: {log_path}")


