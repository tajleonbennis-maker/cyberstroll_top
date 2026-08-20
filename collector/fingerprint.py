"""访客指纹识别 - 精准解析 User-Agent，提取操作系统/浏览器/设备信息"""
import re
import json
from typing import Optional, Dict, List

# ===== 操作系统识别规则 =====
OS_PATTERNS = {
    "Windows": [
        (r"Windows NT 10\.0", "Windows 10/11"),
        (r"Windows NT 6\.[34]", "Windows 8.1/8"),
        (r"Windows NT 6\.[12]", "Windows 7"),
        (r"Windows NT 6\.0", "Windows Vista"),
        (r"Windows NT 5\.[12]", "Windows XP"),
        (r"Windows", "Windows"),
    ],
    "macOS": [
        (r"Mac OS X (\d+[._]\d+)[._]?(\d*)", "macOS {0}.{1}"),
        (r"Macintosh|Macintosh.*Mac OS X", "macOS"),
        (r"Mac_PowerPC", "macOS (PPC)"),
    ],
    "Linux": [
        (r"Linux [x3264_]+; Ubuntu[ /](\d+\.\d+)", "Ubuntu {0}"),
        (r"Linux [x3264_]+; Debian", "Debian"),
        (r"Linux [x3264_]+; Fedora", "Fedora"),
        (r"Linux [x3264_]+; CentOS", "CentOS"),
        (r"Linux [x3264_]+; Red Hat", "RHEL"),
        (r"Linux [x3264_]+; Arch Linux", "Arch Linux"),
        (r"Linux [x3264_]+; Kali", "Kali Linux"),  # 安全工具常用
        (r"Linux", "Linux"),
    ],
    "Android": [
        (r"Android (\d+(\.\d+)*)", "Android {0}"),
        (r"Android", "Android"),
    ],
    "iOS": [
        (r"iPhone OS (\d+_\d+(?:_\d*)?)", "iOS {0}".replace("_", ".")),
        (r"(iPad|iPod|iPhone)", "{0}"),
    ],
    "BSD": [
        (r"FreeBSD", "FreeBSD"),
        (r"OpenBSD", "OpenBSD"),
        (r"NetBSD", "NetBSD"),
    ],
    "Other Unix": [
        (r"Solaris", "Solaris"),
        (r"HP-UX", "HP-UX"),
        (r"AIX", "AIX"),
    ],
}

# ===== 浏览器识别规则 =====
BROWSER_PATTERNS = {
    # 主流浏览器
    "Chrome": [
        (r"Chrome/(\d+\.\d+\.\d+\.\d+)", "Chrome {0}"),
        (r"CriOS/(\d+\.\d+\.\d+\.\d+)", "Chrome iOS {0}"),
    ],
    "Firefox": [
        (r"Firefox/(\d+\.\d+)", "Firefox {0}"),
    ],
    "Safari": [
        (r"Version/(\d+\.\d+).*Safari", "Safari {0}"),
        (r"Safari/(\d+\.\d+)", "Safari {0}"),
    ],
    "Edge": [
        (r"Edg/(\d+\.\d+\.\d+\.\d+)", "Edge {0}"),
        (r"Edge/(\d+\.\d+)", "Edge {0}"),
    ],
    "Opera": [
        (r"OPR/(\d+\.\d+\.\d+\.\d+)", "Opera {0}"),
        (r"Opera/(\d+\.\d+)", "Opera {0}"),
    ],
    # 国内浏览器
    "QQ Browser": [(r"QQBrowser/(\d+\.\d+)", "QQ浏览器 {0}")],
    "360 Browser": [(r"360(?:SE|EE|Browser)/(\d+\.\d+)", "360浏览器 {0}")],
    "UC Browser": [(r"UCBrowser/(\d+\.\d+\.\d+)", "UC浏览器 {0}")],
    "Sogou Browser": [(r"Sogou(?:Mobile)?Browser/(\d+\.\d+)", "搜狗浏览器 {0}")],
    "Maxthon": [(r"Maxthon/(\d+\.\d+)", "傲游浏览器 {0}")],
    "Liebao": [(r"LBBROWSER", "猎豹浏览器")],
    # 命令行工具
    "curl": [(r"^curl/?", "curl")],
    "wget": [(r"Wget/?", "wget")],
    "httpie": [(r"HTTPie/?", "HTTPie")],
    "python-requests": [(r"python-requests", "Python requests")],
    "python-urllib": [(r"Python-urllib", "Python urllib")],
    "Go-http-client": [(r"Go-http-client", "Go HTTP 客户端")],
    "Java": [(r"Java/?", "Java HTTP 客户端")],
    "Ruby": [(r"Ruby", "Ruby HTTP 客户端")],
    "PHP": [(r"PHP/?", "PHP HTTP 客户端")],
    "Node.js": [(r"node(?:-superagent|-fetch)?", "Node.js")],
    "C#": [(r"\.NET/?", ".NET/C# HTTP 客户端")],
}

# ===== 设备类型识别规则 =====
DEVICE_PATTERNS = {
    "Mobile Phone": [
        (r"iPhone", "iPhone"),
        (r"Android.*(Mobile|Pixel|Moto|Samsung|Xiaomi|Huawei|OnePlus|OPPO|vivo|Realme)", "Android 手机"),
        (r"Mobile.*Safari", "移动设备"),
    ],
    "Tablet": [
        (r"iPad", "iPad"),
        (r"Tablet", "平板电脑"),
        (r"Android.*(?!Mobile)", "Android 平板"),
    ],
    "Desktop": [
        (r"Windows NT", "Windows PC"),
        (r"Macintosh", "Mac"),
        (r"Linux [x3264_]+", "Linux 桌面"),
    ],
    "Server/Bot": [
        (r"bot|spider|crawler|slurp|bingbot|googlebot|baiduspider", "爬虫/机器人"),
        (r"python-|php|java|ruby|go-http|curl|wget", "脚本/程序化请求"),
    ],
    "IoT/IoE": [
        (r"SmartTV|AppleTV|Roku|Chromecast|FireTV", "智能电视"),
        (r"PlayStation|Xbox|Nintendo", "游戏主机"),
    ],
}

# ===== CPU 架构识别 =====
ARCH_PATTERNS = {
    "x86_64": [r"x86_64|x64|Win64|amd64|Intel"],
    "ARM64": [r"aarch64|arm64|CPU iPhone OS"],
    "ARM32": [r"armv7l|armv6l|CPU OS"],
    "MIPS": [r"mips|mipsel"],
    "PPC": [r"ppc|powerpc"],
    "Unknown": [],
}

# ===== 扫描器/攻击工具指纹 =====
TOOL_FINGERPRINTS = {
    "Nmap": r"Nmap|NmapNSE",
    "Masscan": r"masscan",
    "Nikto": r"Nikto",
    "DirBuster": r"DirBuster",
    "Gobuster": r"gobuster",
    "WFuzz": r"wfuzz",
    "SQLMap": r"sqlmap",
    "Burp Suite": r"BurpSuite|Burp",
    "OWASP ZAP": r"ZAP|owasp-zap",
    "Acunetix": r"acunetix",
    "Nessus": r"Nessus",
    "OpenVAS": r"openvas",
    "W3AF": r"w3af",
    "WhatWeb": r"WhatWeb",
    "WPScan": r"WPScan",
    "Joomla Scanner": r"Joomla!",
    "Hydra": r"hydra",
    "Medusa": r"medusa",
    "John the Ripper": r"John the Ripper",
    "Metasploit": r"Metasploit",
    "Censys": r"censys",
    "Shodan": r"shodan",
    "BinaryEdge": r"binaryedge",
    "Fofa": r"fofa",
    "ZoomEye": r"zoomeye",
    "Crawler": r"Googlebot|Baiduspider|bingbot|YandexBot|AhrefsBot|SemrushBot|MJ12bot|DotBot",
}


class FingerprintParser:
    """访客指纹解析器"""

    def __init__(self):
        self._cache: Dict[str, dict] = {}

    def parse(self, user_agent: str, ip: str = "") -> dict:
        """
        解析 User-Agent，返回完整指纹信息

        返回结构:
        {
            "user_agent": "...",
            "browser": {"name": "Chrome", "version": "120.0.0.0"},
            "os": {"name": "Windows", "version": "10/11"},
            "device": {"type": "Desktop", "name": "Windows PC"},
            "arch": "x86_64",
            "tool": None or {"name": "Nmap", "category": "scanner"},
            "is_bot": bool,
            "is_mobile": bool,
            "risk_level": "low|medium|high|critical",
            "confidence": float,
            "raw_fingerprint": {...},
        }
        """
        if not user_agent or user_agent == "-":
            return self._empty_fingerprint(user_agent)

        # 缓存检查
        cache_key = f"{user_agent}:{ip}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        ua = user_agent.strip()
        result = {
            "user_agent": ua,
            "ip": ip,
            "browser": self._detect_browser(ua),
            "os": self._detect_os(ua),
            "device": self._detect_device(ua),
            "arch": self._detect_arch(ua),
            "tool": self._detect_tool(ua),
            "is_bot": self._is_bot(ua),
            "is_mobile": self._is_mobile(ua),
            "risk_level": self._assess_risk(ua),
            "confidence": self._calc_confidence(ua),
        }

        # 生成可读的指纹摘要
        result["summary"] = self._generate_summary(result)
        result["icon"] = self._get_device_icon(result)

        # 存入缓存（LRU 简单实现）
        if len(self._cache) > 10000:
            keys = list(self._cache.keys())
            for k in keys[:2000]:
                del self._cache[k]
        self._cache[cache_key] = result

        return result

    def _empty_fingerprint(self, ua: str) -> dict:
        """空/未知指纹"""
        return {
            "user_agent": ua,
            "ip": "",
            "browser": {"name": "Unknown", "version": ""},
            "os": {"name": "Unknown", "version": ""},
            "device": {"type": "Unknown", "name": "Unknown Device"},
            "arch": "Unknown",
            "tool": None,
            "is_bot": False,
            "is_mobile": False,
            "risk_level": "low",
            "confidence": 0.0,
            "summary": "Unknown User-Agent",
            "icon": "❓",
        }

    def _detect_browser(self, ua: str) -> dict:
        """检测浏览器"""
        for browser_name, patterns in BROWSER_PATTERNS.items():
            for pattern, template in patterns:
                match = re.search(pattern, ua, re.IGNORECASE)
                if match:
                    version = ""
                    try:
                        groups = match.groups()
                        if groups and groups[0]:
                            version = groups[0].replace("_", ".")
                        version = template.format(*groups) if "{" in template else template
                    except (IndexError, KeyError):
                        version = template if isinstance(template, str) else browser_name
                    return {"name": browser_name, "version": version}
        return {"name": "Unknown", "version": ""}

    def _detect_os(self, ua: str) -> dict:
        """检测操作系统"""
        for os_name, patterns in OS_PATTERNS.items():
            for pattern, template in patterns:
                match = re.search(pattern, ua, re.IGNORECASE)
                if match:
                    version = ""
                    try:
                        groups = match.groups()
                        if groups and groups[0]:
                            version = groups[0].replace("_", ".")
                        version = template.format(*groups) if "{" in template else os_name
                    except (IndexError, KeyError):
                        version = os_name
                    return {"name": os_name, "version": version}
        return {"name": "Unknown", "version": ""}

    def _detect_device(self, ua: str) -> dict:
        """检测设备类型"""
        for device_type, patterns in DEVICE_PATTERNS.items():
            for pattern, name_template in patterns:
                match = re.search(pattern, ua, re.IGNORECASE)
                if match:
                    device_name = name_template
                    try:
                        groups = match.groups()
                        if groups:
                            device_name = name_template.format(*groups)
                    except (IndexError, KeyError):
                        pass
                    return {"type": device_type, "name": device_name}
        return {"type": "Unknown", "name": "Unknown"}

    def _detect_arch(self, ua: str) -> str:
        """检测 CPU 架构"""
        for arch, patterns in ARCH_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, ua, re.IGNORECASE):
                    return arch
        return "Unknown"

    def _detect_tool(self, ua: str) -> Optional[dict]:
        """检测扫描器/攻击工具"""
        for tool_name, pattern in TOOL_FINGERPRINTS.items():
            if re.search(pattern, ua, re.IGNORECASE):
                category = "scanner"
                if tool_name in ["Crawler"]:
                    category = "crawler"
                elif tool_name in ["Hydra", "Medusa", "John the Ripper"]:
                    category = "brute_force"
                elif tool_name in ["Metasploit"]:
                    category = "exploit"
                elif tool_name in ["Censys", "Shodan", "BinaryEdge", "Fofa", "ZoomEye"]:
                    category = "recon"
                return {"name": tool_name, "category": category}
        return None

    def _is_bot(self, ua: str) -> bool:
        """判断是否为机器人"""
        bot_keywords = [
            "bot", "spider", "crawler", "slurp", "googlebot", "baiduspider",
            "bingbot", "yandexbot", "ahrefsbot", "semrushbot", "mj12bot",
            "dotbot", "curl", "wget", "python-", "java/", "go-http",
            "nmap", "nikto", "sqlmap", "masscan", "wfuzz", "gobuster",
        ]
        ua_lower = ua.lower()
        return any(kw in ua_lower for kw in bot_keywords)

    def _is_mobile(self, ua: str) -> bool:
        """判断是否为移动设备"""
        mobile_keywords = [
            "iphone", "ipad", "android", "mobile", "phone", "tablet",
            "silk", "blackberry", "opera mini", "opera mobi",
        ]
        ua_lower = ua.lower()
        return any(kw in ua_lower for kw in mobile_keywords)

    def _assess_risk(self, ua: str) -> str:
        """评估风险等级"""
        ua_lower = ua.lower()

        # Critical：明确的攻击工具
        critical_tools = ["nmap", "nikto", "sqlmap", "masscan", "dirbuster", "gobuster",
                          "wfuzz", "metasploit", "hydra", "medusa"]
        if any(t in ua_lower for t in critical_tools):
            return "critical"

        # High：安全测试工具
        high_tools = ["burp", "zap", "acunetix", "nessus", "openvas", "w3af",
                      "wpscan", "whatweb"]
        if any(t in ua_lower for t in high_tools):
            return "high"

        # Medium：自动化工具或异常客户端
        medium_indicators = ["python-", "php/", "java ", "go-http", "curl", "wget",
                            "httpie", "libwww", "perl", "ruby", "scrapy"]
        if any(t in ua_lower for t in medium_indicators):
            return "medium"

        # Low：正常浏览器
        return "low"

    def _calc_confidence(self, ua: str) -> float:
        """计算指纹置信度 (0.0 - 1.0)"""
        confidence = 0.5  # 基础分

        # 信息丰富度加分
        if len(ua) > 50:
            confidence += 0.15
        if len(ua) > 100:
            confidence += 0.1

        # 包含版本号加分
        if re.search(r"/\d+\.", ua):
            confidence += 0.15

        # 包含架构信息加分
        if re.search(r"x86_64|arm64|aarch64|i686", ua, re.IGNORECASE):
            confidence += 0.05

        # 非空且不是简单标识
        if ua != "-" and len(ua) > 10:
            confidence += 0.05

        return min(confidence, 1.0)

    def _generate_summary(self, fp: dict) -> str:
        """生成人类可读的指纹摘要"""
        parts = []

        # 设备 + 系统
        device_name = fp["device"].get("name", "")
        os_info = fp["os"].get("version") or fp["os"].get("name", "")
        if device_name and os_info:
            parts.append(f"{device_name} ({os_info})")

        # 浏览器
        browser_ver = fp["browser"].get("version") or fp["browser"].get("name", "")
        if browser_ver:
            parts.append(browser_ver)

        # 工具（如果有）
        if fp.get("tool"):
            parts.append(f"[{fp['tool']['name']}]")

        return " · ".join(parts) if parts else fp.get("user_agent", "Unknown")

    @staticmethod
    def _get_device_icon(fp: dict) -> str:
        """获取设备图标 emoji"""
        device_type = fp.get("device", {}).get("type", "")
        icons = {
            "Mobile Phone": "📱",
            "Tablet": "📱",
            "Desktop": "🖥️",
            "Server/Bot": "🤖",
            "IoT/IoE": "📺",
            "Unknown": "❓",
        }
        return icons.get(device_type, "💻")

    def batch_parse(self, events: List[dict]) -> List[dict]:
        """批量解析事件的指纹"""
        results = []
        for event in events:
            ua = event.get("user_agent", "")
            ip = event.get("source_ip", "")
            fingerprint = self.parse(ua, ip)
            # 合并到事件中
            merged = {**event, "fingerprint": fingerprint}
            results.append(merged)
        return results

    def get_cache_stats(self) -> dict:
        """获取缓存统计"""
        return {
            "cached_entries": len(self._cache),
            "unique_user_agents": len(set(v["user_agent"] for v in self._cache.values())),
        }
