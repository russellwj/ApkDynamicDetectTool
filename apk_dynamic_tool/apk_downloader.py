#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK下载器 - 从URL下载APK文件并验证完整性

数据流: URL -> HTTP下载 -> 本地文件 -> APK验证 -> 返回路径
支持重定向跟随、超时控制、进度显示、断点续传(可选)
"""

import logging
import os
import re
import hashlib
import tempfile
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime
from typing import Optional, Callable

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s', datefmt='%H:%M:%S')
logger = logging.getLogger(__name__)

# APK/ZIP 文件魔数: PK\x03\x04
APK_MAGIC = b'PK\x03\x04'

# 允许的Content-Type
VALID_CONTENT_TYPES = {
    'application/vnd.android.package-archive',
    'application/octet-stream',
    'application/zip',
    'application/x-zip-compressed',
    'binary/octet-stream',
    'application/x-apk',
    'application/java-archive',
}


class ApkDownloadError(Exception):
    """APK下载失败异常"""


class ApkDownloader:
    """从URL下载APK文件"""

    DEFAULT_DOWNLOAD_DIR = 'apk_input'
    DEFAULT_TIMEOUT = 300
    CHUNK_SIZE = 8192

    def __init__(
        self,
        download_dir: Optional[str] = None,
        timeout: int = DEFAULT_TIMEOUT,
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ):
        """
        Args:
            download_dir: 下载目录, 默认 apk_input/
            timeout: 下载超时(秒), 默认300
            progress_callback: 进度回调(downloaded_bytes, total_bytes)
        """
        self.download_dir = Path(download_dir) if download_dir else Path(self.DEFAULT_DOWNLOAD_DIR)
        self.timeout = timeout
        self.progress_callback = progress_callback

    def download(self, url: str, filename: Optional[str] = None) -> Path:
        """
        从URL下载APK文件

        Args:
            url: APK下载地址
            filename: 保存文件名(不含路径), None则从URL推断

        Returns:
            下载后的本地文件路径

        Raises:
            ApkDownloadError: 下载失败
        """
        if not self._validate_url(url):
            raise ApkDownloadError(f"无效的URL: {url}")

        if not filename:
            filename = self._infer_filename(url)

        if not filename.lower().endswith('.apk'):
            filename = filename + '.apk'

        self.download_dir.mkdir(parents=True, exist_ok=True)
        local_path = self.download_dir / filename

        logger.info(f"开始下载: {url}")
        logger.info(f"   保存到: {local_path}")

        try:
            self._download_file(url, local_path)
        except ApkDownloadError:
            raise
        except Exception as e:
            if local_path.exists():
                local_path.unlink()
            raise ApkDownloadError(f"下载失败: {e}") from e

        file_size = local_path.stat().st_size
        logger.info(f"下载完成: {local_path.name} ({file_size / 1024 / 1024:.1f} MB)")

        if not self._validate_apk(local_path):
            logger.warning("下载的文件可能不是有效的APK(魔数不匹配), 继续处理")

        return local_path

    def _download_file(self, url: str, dest: Path) -> None:
        """执行HTTP下载, 支持重定向和进度"""
        req = urllib.request.Request(url)
        req.add_header('User-Agent', 'ApkDynamicDetectTool/1.0')

        try:
            response = urllib.request.urlopen(req, timeout=self.timeout)
        except urllib.error.HTTPError as e:
            raise ApkDownloadError(f"HTTP错误 {e.code}: {e.reason}")
        except urllib.error.URLError as e:
            raise ApkDownloadError(f"URL错误: {e.reason}")

        total_size = int(response.headers.get('Content-Length', 0))

        content_type = response.headers.get('Content-Type', '')
        if content_type and content_type not in VALID_CONTENT_TYPES:
            logger.debug(f"Content-Type: {content_type} (非标准APK类型, 继续下载)")

        downloaded = 0
        md5 = hashlib.md5()

        with open(dest, 'wb') as f:
            while True:
                chunk = response.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                f.write(chunk)
                md5.update(chunk)
                downloaded += len(chunk)
                if self.progress_callback:
                    self.progress_callback(downloaded, total_size)

        if total_size > 0 and downloaded != total_size:
            raise ApkDownloadError(
                f"下载不完整: 已下载 {downloaded} / 预期 {total_size} 字节"
            )

        logger.info(f"   MD5: {md5.hexdigest()}")
        response.close()

    @staticmethod
    def _validate_url(url: str) -> bool:
        """验证URL格式"""
        if not url or not isinstance(url, str):
            return False
        return url.startswith('http://') or url.startswith('https://')

    @staticmethod
    def _infer_filename(url: str) -> str:
        """从URL推断文件名, 推不掉则用时间戳"""
        # 去掉query和fragment
        path = url.split('?')[0].split('#')[0]
        # 取URL的path部分(去掉协议和域名)
        # https://example.com/path/to/file.apk -> /path/to/file.apk
        parts = path.split('/', 3)
        if len(parts) >= 4 and parts[3]:
            url_path = parts[3]
        else:
            url_path = ''
        basename = url_path.rstrip('/').rsplit('/', 1)[-1] if url_path else ''
        if basename and re.match(r'^[\w.\-]+$', basename) and '.' in basename:
            return basename
        return f"apk_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

    @staticmethod
    def _validate_apk(path: Path) -> bool:
        """通过魔数验证文件是否为APK(ZIP)格式"""
        try:
            with open(path, 'rb') as f:
                magic = f.read(4)
            return magic == APK_MAGIC
        except Exception:
            return False

    def download_batch(self, urls: list) -> list:
        """
        批量下载多个URL

        Args:
            urls: URL列表

        Returns:
            (successes, failures) 二元组列表:
            [(True, Path), (False, error_msg), ...]
        """
        results = []
        for url in urls:
            try:
                path = self.download(url)
                results.append((True, path))
            except ApkDownloadError as e:
                logger.error(f"下载失败: {url} -> {e}")
                results.append((False, str(e)))
        return results
