"""数据存储 - SQLite 持久化攻击数据"""
import json
import os
import sqlite3
import threading
from datetime import datetime, timezone, timedelta
from typing import Optional

CST = timezone(timedelta(hours=8))
DEFAULT_DB_PATH = "/opt/cyberstroll/data/attacks.db"

# 数据库 schema
SCHEMA = """
CREATE TABLE IF NOT EXISTS attacks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL NOT NULL,
    time_str TEXT,
    source_ip TEXT NOT NULL,
    attack_type TEXT,
    attack_severity TEXT,
    method TEXT,
    path TEXT,
    status INTEGER,
    user_agent TEXT,
    referer TEXT,
    raw_data TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_attacks_timestamp ON attacks(timestamp);
CREATE INDEX IF NOT EXISTS idx_attacks_ip ON attacks(source_ip);
CREATE INDEX IF NOT EXISTS idx_attacks_type ON attacks(attack_type);

CREATE TABLE IF NOT EXISTS daily_stats (
    date TEXT PRIMARY KEY,
    total_attacks INTEGER DEFAULT 0,
    unique_ips INTEGER DEFAULT 0,
    by_type TEXT DEFAULT '{}',
    by_severity TEXT DEFAULT '{}',
    top_attackers TEXT DEFAULT '[]',
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
"""


class AttackStorage:
    """线程安全的攻击数据存储"""

    def __init__(self, db_path: str = DEFAULT_DB_PATH):
        self.db_path = db_path
        self._lock = threading.Lock()
        self._ensure_db()

    def _ensure_db(self):
        """确保数据库和目录存在"""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.executescript(SCHEMA)
        conn.commit()
        conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        """获取数据库连接"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def insert_attack(self, event: dict) -> int:
        """插入一条攻击记录，返回插入的 ID"""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.execute(
                """INSERT INTO attacks
                (timestamp, time_str, source_ip, attack_type, attack_severity,
                 method, path, status, user_agent, referer, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event.get("timestamp"),
                    event.get("time_str"),
                    event.get("source_ip"),
                    event.get("attack_type"),
                    event.get("attack_severity"),
                    event.get("method"),
                    event.get("path"),
                    event.get("status"),
                    event.get("user_agent"),
                    event.get("referer"),
                    json.dumps(event, ensure_ascii=False),
                ),
            )
            row_id = cursor.lastrowid
            conn.commit()
            conn.close()
            return row_id

    def insert_attacks_batch(self, events: list[dict]) -> int:
        """批量插入攻击记录"""
        if not events:
            return 0

        with self._lock:
            conn = self._get_conn()
            count = 0
            for event in events:
                conn.execute(
                    """INSERT INTO attacks
                    (timestamp, time_str, source_ip, attack_type, attack_severity,
                     method, path, status, user_agent, referer, raw_data)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        event.get("timestamp"),
                        event.get("time_str"),
                        event.get("source_ip"),
                        event.get("attack_type"),
                        event.get("attack_severity"),
                        event.get("method"),
                        event.get("path"),
                        event.get("status"),
                        event.get("user_agent"),
                        event.get("referer"),
                        json.dumps(event, ensure_ascii=False),
                    ),
                )
                count += 1
            conn.commit()
            conn.close()
            return count

    def get_recent_attacks(self, limit: int = 100) -> list[dict]:
        """获取最近的攻击记录"""
        conn = self._get_conn()
        rows = conn.execute(
            "SELECT * FROM attacks ORDER BY timestamp DESC LIMIT ?", (limit,)
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_attacks_by_time_range(
        self, start_time: float, end_time: Optional[float] = None
    ) -> list[dict]:
        """获取时间范围内的攻击"""
        conn = self._get_conn()
        if end_time:
            rows = conn.execute(
                "SELECT * FROM attacks WHERE timestamp BETWEEN ? AND ? ORDER BY timestamp",
                (start_time, end_time),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM attacks WHERE timestamp >= ? ORDER BY timestamp",
                (start_time,),
            ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_top_attackers(self, limit: int = 20) -> list[dict]:
        """获取 TOP 攻击者 IP"""
        conn = self._get_conn()
        rows = conn.execute(
            """SELECT source_ip, COUNT(*) as count,
                      MIN(timestamp) as first_seen,
                      MAX(timestamp) as last_seen,
                      GROUP_CONCAT(DISTINCT attack_type) as attack_types
               FROM attacks
               GROUP BY source_ip
               ORDER BY count DESC
               LIMIT ?""",
            (limit,),
        ).fetchall()
        conn.close()
        return [dict(r) for r in rows]

    def get_attack_stats(self, hours: int = 24) -> dict:
        """获取统计信息"""
        import time as _time

        since = _time.time() - hours * 3600
        conn = self._get_conn()

        total = conn.execute(
            "SELECT COUNT(*) FROM attacks WHERE timestamp >= ?", (since,)
        ).fetchone()[0]

        unique_ips = conn.execute(
            "SELECT COUNT(DISTINCT source_ip) FROM attacks WHERE timestamp >= ?",
            (since,),
        ).fetchone()[0]

        # 按类型统计
        type_rows = conn.execute(
            """SELECT attack_type, COUNT(*) as cnt
               FROM attacks WHERE timestamp >= ?
               GROUP BY attack_type ORDER BY cnt DESC""",
            (since,),
        ).fetchall()
        by_type = {r["attack_type"] or "unknown": r["cnt"] for r in type_rows}

        # 按严重程度统计
        sev_rows = conn.execute(
            """SELECT attack_severity, COUNT(*) as cnt
               FROM attacks WHERE timestamp >= ?
               GROUP BY attack_severity""",
            (since,),
        ).fetchall()
        by_severity = {r["attack_severity"] or "unknown": r["cnt"] for r in sev_rows}

        # 按小时分布（用于时间线图表）
        hour_rows = conn.execute(
            """SELECT strftime('%H', datetime(timestamp, 'unixepoch', 'localtime')) as hour,
                      COUNT(*) as cnt
               FROM attacks WHERE timestamp >= ?
               GROUP BY hour ORDER BY hour""",
            (since,),
        ).fetchall()
        timeline = {int(r["hour"]): r["cnt"] for r in hour_rows}

        conn.close()

        return {
            "period_hours": hours,
            "total_attacks": total,
            "unique_ips": unique_ips,
            "by_type": by_type,
            "by_severity": by_severity,
            "timeline": timeline,
        }

    def get_total_count(self) -> int:
        """获取总攻击数"""
        conn = self._get_conn()
        count = conn.execute("SELECT COUNT(*) FROM attacks").fetchone()[0]
        conn.close()
        return count

    def cleanup_old_records(self, days: int = 30):
        """清理旧记录"""
        import time as _time

        cutoff = _time.time() - days * 86400
        conn = self._get_conn()
        deleted = conn.execute(
            "DELETE FROM attacks WHERE timestamp < ?", (cutoff,)
        ).rowcount
        conn.commit()
        conn.close()
        return deleted
