"""攻击分类器 - 聚合攻击事件，识别攻击模式"""
import time
from collections import defaultdict
from typing import Optional


class AttackClassifier:
    """攻击事件聚合与分类"""

    # 端口扫描检测窗口（秒）
    SCAN_WINDOW = 60
    # 窗口内多少次不同端口连接算扫描
    SCAN_THRESHOLD = 10

    def __init__(self):
        # IP -> {timestamp, port_count, ports}
        self._connection_tracker: dict[str, dict] = {}
        # 清理周期
        self._last_cleanup = time.time()

    def classify(self, event: dict) -> dict:
        """对单个事件进行增强分类"""
        ip = event["source_ip"]

        # 追踪连接用于检测端口扫描
        self._track_connection(ip, event)

        # 检测是否为端口扫描
        scan_info = self._detect_port_scan(ip)
        if scan_info:
            event["attack_type"] = "port_scan"
            event["attack_severity"] = "medium"
            event["scan_detail"] = scan_info

        return event

    def _track_connection(self, ip: str, event: dict):
        """追踪 IP 连接"""
        now = time.time()

        if ip not in self._connection_tracker:
            self._connection_tracker[ip] = {
                "first_seen": now,
                "last_seen": now,
                "connections": 0,
                "ports": set(),
                "paths": [],
            }

        tracker = self._connection_tracker[ip]
        tracker["last_seen"] = now
        tracker["connections"] += 1

        # 记录路径（去重，最多保留 50 个）
        path = event.get("path", "")
        if path and path not in tracker["paths"][-50:]:
            tracker["paths"].append(path)

        # 定期清理过期数据
        if now - self._last_cleanup > 300:  # 5分钟清理一次
            self._cleanup(now)
            self._last_cleanup = now

    def _detect_port_scan(self, ip: str) -> Optional[dict]:
        """检测端口扫描行为"""
        if ip not in self._connection_tracker:
            return None

        tracker = self._connection_tracker[ip]
        now = time.time()
        elapsed = now - tracker["first_seen"]

        # 检查短时间内大量不同路径访问（HTTP 层面的"端口扫描"）
        unique_paths = len(tracker["paths"])
        if (
            elapsed < self.SCAN_WINDOW
            and unique_paths >= self.SCAN_THRESHOLD
            and tracker["connections"] >= self.SCAN_THRESHOLD * 2
        ):
            return {
                "unique_paths": unique_paths,
                "total_connections": tracker["connections"],
                "time_window": f"{elapsed:.1f}s",
                "sample_paths": tracker["paths"][:10],
            }
        return None

    def _cleanup(self, now: float):
        """清理过期的追踪数据"""
        expired = [
            ip for ip, t in self._connection_tracker.items()
            if now - t["last_seen"] > 3600  # 1小时无活动则清理
        ]
        for ip in expired:
            del self._connection_tracker[ip]

    def get_ip_stats(self, ip: str) -> Optional[dict]:
        """获取指定 IP 的统计信息"""
        return self._connection_tracker.get(ip)

    def get_top_attackers(self, limit: int = 20) -> list[dict]:
        """获取 TOP 攻击者排行"""
        stats = []
        for ip, tracker in self._connection_tracker.items():
            stats.append({
                "ip": ip,
                "connections": tracker["connections"],
                "unique_paths": len(tracker["paths"]),
                "duration": tracker["last_seen"] - tracker["first_seen"],
                "first_seen": tracker["first_seen"],
                "last_seen": tracker["last_seen"],
            })

        # 按连接数排序
        stats.sort(key=lambda x: x["connections"], reverse=True)
        return stats[:limit]

    def get_attack_summary(self) -> dict:
        """获取攻击总览统计"""
        total_ips = len(self._connection_tracker)
        total_connections = sum(t["connections"] for t in self._connection_tracker.values())

        type_counts: dict[str, int] = defaultdict(int)
        severity_counts: dict[str, int] = defaultdict(int)

        for tracker in self._connection_tracker.values():
            for path in tracker["paths"]:
                # 简单的路径特征分类
                path_lower = path.lower()
                if any(x in path_lower for x in ["union", "select", "insert", "drop"]):
                    type_counts["sql_injection"] += 1
                    severity_counts["high"] += 1
                elif any(x in path_lower for x in ["script", "javascript:", "onerror"]):
                    type_counts["xss"] += 1
                    severity_counts["high"] += 1
                elif "../" in path or "..%2f" in path or "%2e%2e" in path:
                    type_counts["path_traversal"] += 1
                    severity_counts["medium"] += 1
                elif any(x in path_lower for x in [".env", ".git", "wp-admin", "phpmyadmin"]):
                    type_counts["sensitive_file"] += 1
                    severity_counts["medium"] += 1
                else:
                    type_counts["suspicious_request"] += 1
                    severity_counts["low"] += 1

        return {
            "total_unique_ips": total_ips,
            "total_attacks": total_connections,
            "by_type": dict(type_counts),
            "by_severity": dict(severity_counts),
        }
