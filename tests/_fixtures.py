#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""测试共享夹具: 合成TLS ClientHello / mock device / mock adb"""

from pathlib import Path
from unittest.mock import MagicMock

# 项目根目录(测试从这里启动)
PROJECT_ROOT = Path(__file__).resolve().parent.parent

# apk_input目录(端到端测试用)
APK_INPUT_DIR = PROJECT_ROOT / 'apk_input'


def build_tls_client_hello_with_sni(hostname: str) -> bytes:
    """构造一个最小化的 TLS ClientHello 字节流(含 SNI 扩展)。

    TLS记录层: content_type(1)=0x16, version(2)=0x0301, length(2)
    Handshake: type(1)=0x01, length(3), version(2)=0x0303, random(32),
      session_id_len(1), session_id, cipher_suites_len(2), cipher_suites,
      comp_methods_len(1), comp_methods, extensions_len(2), extensions
    扩展: SNI type=0x0000, ext_len(2), list_len(2),
      name_type(1)=0x00, name_len(2), name
    """
    name = hostname.encode('ascii')
    name_entry = b'\x00' + len(name).to_bytes(2, 'big') + name
    list_len = len(name_entry).to_bytes(2, 'big')
    sni_ext_data = list_len + name_entry
    sni_ext = b'\x00\x00' + len(sni_ext_data).to_bytes(2, 'big') + sni_ext_data

    extensions = sni_ext
    extensions_block = len(extensions).to_bytes(2, 'big') + extensions

    cipher_suites = b'\x00\x2f'  # TLS_RSA_WITH_AES_128_CBC_SHA
    cipher_block = len(cipher_suites).to_bytes(2, 'big') + cipher_suites
    comp_block = b'\x01\x00'  # 1 method: null

    hello_body = (b'\x03\x03' + b'\x00' * 32 +  # version + random
                  b'\x00' +  # session_id_len = 0
                  cipher_block + comp_block + extensions_block)
    handshake = b'\x01' + len(hello_body).to_bytes(3, 'big') + hello_body
    tls_record = b'\x16\x03\x01' + len(handshake).to_bytes(2, 'big') + handshake
    return tls_record


class FakeUIElement:
    """模拟 uiautomator2 的 UI 元素对象。"""

    def __init__(self, exists: bool = False, info: dict = None):
        self._exists = exists
        self._info = info or {}
        self.clicked = False
        self.sibling_clicked = False

    @property
    def exists(self) -> bool:
        return self._exists

    def click(self):
        self.clicked = True

    def info_get(self):
        return self._info

    def sibling(self, className='*'):
        # 返回另一个可点击对象, 供 handle_permission_dialogs 的 parent.info.get('text', '') 路径
        return FakeUIElement(exists=True, info={'text': '风险管控中心'})

    def __call__(self, *args, **kwargs):
        # device(text=..., clickable=True) 调用返回自身
        return self


class FakeDevice:
    """模拟 uiautomator2.Device, 仅实现测试中用到的接口。"""

    def __init__(self):
        self.app_current_value = {'package': '', 'activity': ''}
        self.clicks = []
        self.swipes = []
        self.back_presses = 0
        self.screenshots_taken = 0
        self._elements = {}

    def __call__(self, **kwargs):
        # device(text=..., clickable=True) / device(resourceId=...) / device(textContains=...)
        key = tuple(sorted(kwargs.items()))
        if key not in self._elements:
            self._elements[key] = FakeUIElement(exists=False)
        return self._elements[key]

    def set_element(self, **kwargs):
        """注入一个"存在"的元素, 后续用同样的 kwargs 查询可拿到。"""
        key = tuple(sorted(kwargs.items()))
        elem = FakeUIElement(exists=True, info=kwargs)
        self._elements[key] = elem
        return elem

    def app_current(self):
        return dict(self.app_current_value)

    def click(self, x, y):
        self.clicks.append((x, y))

    def swipe(self, *args):
        self.swipes.append(args)

    def press(self, key):
        if key == 'back':
            self.back_presses += 1

    def screenshot(self, path):
        self.screenshots_taken += 1
        Path(path).write_bytes(b'fake-png')

    def window_size(self):
        return (1080, 1920)


class FakeSubprocessResult:
    def __init__(self, returncode=0, stdout='', stderr=''):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def make_adb_with_responses(response_map, default_response=None):
    """构造一个 ADBHelper, 其 run_adb 按参数匹配返回预设响应。

    response_map: {(arg_tuple_substring): (ret, stdout, stderr), ...}
    匹配规则: 任一 key 是 args 列表的子串(空格分隔), 即命中。
    """
    from apk_dynamic_tool.adb_helper import ADBHelper

    adb = ADBHelper(device_id='fake-device-001')

    def fake_run_adb(args, timeout=60):
        args_str = ' '.join(args)
        for key, resp in response_map.items():
            if key in args_str:
                return resp
        return default_response or (0, '', '')

    adb.run_adb = fake_run_adb  # type: ignore
    return adb
