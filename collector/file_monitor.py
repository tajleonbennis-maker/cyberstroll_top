"""文件访问监控系统 - 实时追踪系统中被访问的文件和目录"""
import os
import time
import threading
import json
from datetime import datetime, timezone, timedelta
from typing import Optional

CST = timezone(timedelta(hours=8))

# 默认监控路径（可配置）
DEFAULT_WATCH_PATHS = [
    "/var/www",
    "/etc/nginx",
    "/opt/cyberstroll",
    "/tmp",
    "/home",
]

# 敏感路径模式（高亮显示）
SENSITIVE_PATTERNS = [
    "/etc/shadow",
    "/etc/passwd",
    ".env",
    ".git",
    "id_rsa",
    "id_dsa",
    ".ssh/",
    "wp-config",
    "database.yml",
    "credentials",
    "secret",
    ".htpasswd",
]

# 文件操作类型中文映射
ACTION_LABELS = {
    "access": "📖 访问",
    "modify": "✏️ 修改",
    "create": "➕ 创建",
    "delete": "🗑️ 删除",
    "move": "📦 移动",
}


class FileMonitor:
    """基于 inotify 的文件访问监控器"""

    def __init__(self, storage=None, watch_paths=None):
        self.storage = storage
        self.watch_paths = watch_paths or DEFAULT_WATCH_PATHS
        self._running = False
        self._thread = None
        self._recent_events = []  # 内存中最近的事件（用于 API 快速返回）
        self._max_recent = 200

    def start(self):
        """启动监控"""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        print(f"[FileMonitor] 已启动，监控路径: {self.watch_paths}")

    def stop(self):
        """停止监控"""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _monitor_loop(self):
        """监控主循环"""
        # 尝试使用 inotify（Linux）
        try:
            self._inotify_monitor()
        except ImportError:
            # 回退到轮询模式
            print("[FileMonitor] inotify 不可用，使用轮询模式")
            self._polling_monitor()

    def _inotify_monitor(self):
        """基于 inotify 的监控（需要 pyinotify）"""
        import pyinotify

        mask = (
            pyinotify.IN_ACCESS |
            pyinotify.IN_MODIFY |
            pyinotify.IN_CREATE |
            pyinotify.IN_DELETE |
            pyinotify.IN_MOVED_FROM |
            pyinotify.IN_MOVED_TO |
            pyinotify.IN_OPEN
        )

        class EventHandler(pyinotify.ProcessEvent):
            def __init__(self, monitor):
                self.monitor = monitor

            def process_default(self, event):
                action = self._classify_action(event.maskname)
                self.monitor._on_file_event(
                    pathname=event.pathname,
                    is_dir=event.dir,
                    action=action,
                    source="inotify"
                )

            @staticmethod
            def _classify_action(maskname):
                if "ACCESS" in maskname or "OPEN" in maskname:
                    return "access"
                elif "MODIFY" in maskname:
                    return "modify"
                elif "CREATE" in maskname or "MOVED_TO" in maskname:
                    return "create"
                elif "DELETE" in maskname or "MOVED_FROM" in maskname:
                    return "delete"
                else:
                    return "access"

        wm = pyinotify.WatchManager()
        handler = EventHandler(self)
        notifier = pyinotify.Notifier(wm, handler)

        for path in self.watch_paths:
            if os.path.exists(path):
                try:
                    wm.add_watch(path, mask, rec=True, auto_add=True)
                    print(f"[FileMonitor] 监控: {path}")
                except Exception as e:
                    print(f"[FileMonitor] 无法监控 {path}: {e}")

        notifier.loop()

    def _polling_monitor(self):
        """回退的轮询监控模式"""
        # 记录文件状态：path -> mtime
        file_states = {}

        while self._running:
            for watch_path in self.watch_paths:
                self._scan_directory(watch_path, file_states)
            time.sleep(2)  # 2秒轮询一次

    def _scan_directory(self, directory, file_states):
        """扫描目录变化"""
        try:
            for root, dirs, files in os.walk(directory):
                # 跳过隐藏目录和 .git
                dirs[:] = [d for d in dirs if not d.startswith('.') and d != '.git']

                for fname in files:
                    fpath = os.path.join(root, fname)
                    try:
                        current_mtime = os.path.getmtime(fpath)
                        last_mtime = file_states.get(fpath)

                        if last_mtime is None:
                            # 新文件
                            self._on_file_event(
                                pathname=fpath,
                                is_dir=False,
                                action="create",
                                source="poll"
                            )
                        elif current_mtime > last_mtime:
                            # 文件被修改或访问
                            self._on_file_event(
                                pathname=fpath,
                                is_dir=False,
                                action="access",
                                source="poll"
                            )

                        file_states[fpath] = current_mtime
                    except (OSError, IOError):
                        pass
        except (OSError, PermissionError) as e:
            pass  # 跳过无权限的目录

    def _on_file_event(self, pathname: str, is_dir: bool, action: str, source: str):
        """处理文件事件"""
        now = time.time()
        event = {
            "timestamp": now,
            "time_str": datetime.fromtimestamp(now, tz=CST).isoformat(),
            "pathname": pathname,
            "is_dir": is_dir,
            "action": action,
            "action_label": ACTION_LABELS.get(action, action),
            "source": source,
            "is_sensitive": self._check_sensitive(pathname),
            "size": self._get_size(pathname) if not is_dir else None,
        }

        # 添加到内存缓存
        self._recent_events.insert(0, event)
        if len(self._recent_events) > self._max_recent:
            self._recent_events.pop()

        # 存储到数据库（如果可用）
        if self.storage:
            try:
                self.storage.insert_file_event(event)
            except Exception as e:
                pass  # 存储失败不影响监控

    @staticmethod
    def _check_sensitive(pathname: str) -> bool:
        """检查是否为敏感路径"""
        path_lower = pathname.lower()
        return any(p.lower() in path_lower for p in SENSITIVE_PATTERNS)

    @staticmethod
    def _get_size(pathname: str) -> Optional[int]:
        """获取文件大小"""
        try:
            return os.path.getsize(pathname)
        except (OSError, IOError):
            return None

    def get_recent_events(self, limit: int = 50) -> list[dict]:
        """获取最近的文件事件"""
        return self._recent_events[:limit]

    def get_stats(self) -> dict:
        """获取监控统计"""
        total = len(self._recent_events)
        sensitive_count = sum(1 for e in self._recent_events if e.get("is_sensitive"))

        # 按操作类型统计
        action_counts = {}
        for e in self._recent_events:
            action = e.get("action", "unknown")
            action_counts[action] = action_counts.get(action, 0) + 1

        # 热门目录（按访问次数排序）
        dir_counts = {}
        for e in self._recent_events:
            dirname = os.path.dirname(e.get("pathname", ""))
            dir_counts[dirname] = dir_counts.get(dirname, 0) + 1

        top_dirs = sorted(dir_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        return {
            "total_events": total,
            "sensitive_events": sensitive_count,
            "watching_paths": self.watch_paths,
            "by_action": action_counts,
            "top_directories": [{"path": d, "count": c} for d, c in top_dirs],
        }
