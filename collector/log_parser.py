"""攻击数据收集器 - 解析系统日志，提取攻击事件"""
import re
import json
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Optional

# 时区（UTC+8）
CST = timezone(timedelta(hours=8))


class LogParser:
    """日志解析器基类"""

    def __init__(self, log_path: str):
        self.log_path = log_path
        self.last_position = 0
        self._load_position()

    def _load_position(self):
        """加载上次读取位置"""
        pos_file = f"{self.log_path}.pos"
        if os.path.exists(pos_file):
            try:
                with open(pos_file) as f:
                    self.last_position = int(f.read().strip())
            except (ValueError, IOError):
                self.last_position = 0

    def _save_position(self):
        """保存读取位置"""
        pos_file = f"{self.log_path}.pos"
        with open(pos_file, "w") as f:
            f.write(str(self.last_position))

    def get_new_lines(self) -> list[str]:
        """获取新增的日志行"""
        if not os.path.exists(self.log_path):
            return []

        file_size = os.path.getsize(self.log_path)

        # 日志轮转检测：文件变小了，从头读
        if file_size < self.last_position:
            self.last_position = 0

        if file_size == self.last_position:
            return []

        lines = []
        with open(self.log_path, "r", errors="ignore") as f:
            f.seek(self.last_position)
            for line in f:
                line = line.strip()
                if line:
                    lines.append(line)
            self.last_position = f.tell()

        self._save_position()
        return lines


class NginxLogParser(LogParser):
    """Nginx 访问日志解析"""

    # Nginx combined 格式正则
    PATTERN = re.compile(
        r'(?P<ip>[\d.:a-fA-F]+)\s+'
        r'-\s+'  # ident
        r'(?P<user>\S+)\s+'
        r'\[(?P<time>[^\]]+)\]\s+'
        r'"(?P<method>\w+)\s+(?P<path>\S+)\s+\S+"\s+'  # request
        r'(?P<status>\d{3})\s+'
        r'(?P<size>\d+|-)\s+'
        r'"(?P<referer>[^"]*)"\s+'
        r'"(?P<ua>[^"]*)"'
    )

    # 攻击特征规则
    ATTACK_RULES = {
        "sql_injection": [
            r"(?i)union\s+(all\s+)?select",
            r"(?i)'\s*or\s*'",
            r"(?i)1\s*=\s*1",
            r"(?i);\s*drop\s",
            r"(?i)'\s*;\s*--",
            r"(?i)exec\s+xp_",
            r"(?i)information_schema",
            r"(?i)concat\s*\(",
        ],
        "xss": [
            r"(?i)<script",
            r"(?i)javascript:",
            r"(?i)onerror\s*=",
            r"(?i)onload\s*=",
            r"(?i)alert\s*\(",
            r"(?i)document\.cookie",
            r"(?i)eval\s*\(",
            r"(?i)expression\s*\(",
        ],
        "path_traversal": [
            r"\.\./|\.\.\\|%2e%2e|%2e/|\.\.%2f",
            r"(?i)/etc/passwd|/etc/shadow|/proc/|/sys/|wp-config",
        ],
        "scanner_fingerprint": [
            r"(?i)nmap|masscan|nikto|dirbuster|gobuster|wfuzz|sqlmap",
            r"(?i)acunetix|nessus|openvas|burpsuite|zap|w3af|whatweb",
        ],
        "sensitive_file": [
            r"(?i)\.env|\.git|\.svn|\.htaccess|\.htpasswd",
            r"(?i)wp-admin|phpmyadmin|admin\.php|server-status|\.DS_Store",
        ],
        "cmd_injection": [
            r"(?i);\s*(ls|cat|wget|curl|bash|sh|python|perl|nc)",
            r"(?i)\|\s*(ls|cat|wget|curl)",
            r"`[^`]+`",
            r"\$\([^)]+\)",
        ],
    }

    def parse_line(self, line: str) -> Optional[dict]:
        """解析单行 nginx 日志"""
        match = self.PATTERN.match(line)
        if not match:
            return None

        data = match.groupdict()

        # 解析时间
        try:
            dt = datetime.strptime(data["time"], "%d/%b/%Y:%H:%M:%S %z")
            timestamp = dt.timestamp()
        except ValueError:
            timestamp = time.time()

        result = {
            "timestamp": timestamp,
            "time_str": datetime.fromtimestamp(timestamp, tz=CST).isoformat(),
            "source_ip": data["ip"],
            "method": data["method"],
            "path": data["path"],
            "status": int(data["status"]),
            "user_agent": data["ua"],
            "referer": data["referer"],
            "size": data["size"],
            "attack_type": None,
            "attack_severity": None,
        }

        # 检测攻击类型
        target = data["path"] + " " + data["ua"]
        for attack_type, patterns in self.ATTACK_RULES.items():
            for pattern in patterns:
                if re.search(pattern, target):
                    result["attack_type"] = attack_type
                    result["attack_severity"] = self._get_severity(attack_type)
                    break
            if result["attack_type"]:
                break

        # 额外检测：4xx 大量请求可能是扫描
        if not result["attack_type"] and int(data["status"]) >= 400:
            result["attack_type"] = "suspicious_request"
            result["attack_severity"] = "low"

        # 所有访问都记录：正常访问标记为 normal_access
        if not result["attack_type"]:
            result["attack_type"] = "normal_access"
            result["attack_severity"] = "info"

        return result

    @staticmethod
    def _get_severity(attack_type: str) -> str:
        high = {"sql_injection", "xss", "cmd_injection"}
        medium = {"path_traversal", "sensitive_file"}
        if attack_type in high:
            return "high"
        elif attack_type in medium:
            return "medium"
        return "low"


class AuthLogParser(LogParser):
    """系统认证日志解析（auth.log）"""

    # SSH 暴力破解 / 失败登录
    FAILED_AUTH_PATTERN = re.compile(
        r'(?:Failed password|Invalid user|Accepted password|'
        r'Connection closed by|Possible break-in attempt).*?'
        r'(?:from|for)\s+(\S+)'
    )
    PORT_SCAN_HINT = re.compile(
        r'Connection closed by (\S+):*\s*(?:port \d+)?'
    )

    def parse_line(self, line: str) -> Optional[dict]:
        """解析 auth.log 行"""
        match = self.FAILED_AUTH_PATTERN.search(line)
        if not match:
            return None

        ip = match.group(1)
        timestamp = time.time()

        is_failed = any(kw in line.lower() for kw in ["failed", "invalid", "break-in"])

        return {
            "timestamp": timestamp,
            "time_str": datetime.fromtimestamp(timestamp, tz=CST).isoformat(),
            "source_ip": ip,
            "attack_type": "ssh_brute_force" if is_failed else "ssh_connection",
            "attack_severity": "high" if is_failed else "low",
            "method": "SSH",
            "path": line.strip()[:200],  # 原始日志截断
            "status": 401 if is_failed else 200,
            "user_agent": "ssh-client",
            "referer": "-",
            "size": "-",
        }
