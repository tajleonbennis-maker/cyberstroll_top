"""CyberStroll Top - Dashboard Flask 服务器"""
import os
import sys
import json
import time
import threading
import socket
import subprocess
import re
from datetime import datetime, timezone, timedelta
from urllib.request import urlopen

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, request

# 导入收集器模块
from collector.log_parser import NginxLogParser, AuthLogParser
from collector.attack_classifier import AttackClassifier
from collector.storage import AttackStorage
from collector.file_monitor import FileMonitor
from collector.fingerprint import FingerprintParser

# 配置
CONFIG = {
    "dashboard_port": int(os.environ.get("DASHBOARD_PORT", 8090)),
    "nginx_log": os.environ.get("NGINX_LOG", "/var/log/nginx/cyberstroll.top.access.log"),
    "auth_log": os.environ.get("AUTH_LOG", "/var/log/auth.log"),
    "db_path": os.environ.get("DB_PATH", "/opt/cyberstroll/data/attacks.db"),
    "scan_interval": int(os.environ.get("SCAN_INTERVAL", 5)),  # 秒
    "honeypot_ssh_port": int(os.environ.get("HONEYPOT_SSH_PORT", 2222)),
    "honeypot_http_port": int(os.environ.get("HONEYPOT_HTTP_PORT", 8088)),
    # 文件监控路径（逗号分隔）
    "watch_paths": os.environ.get("WATCH_PATHS", "").split(",") if os.environ.get("WATCH_PATHS") else None,
}

app = Flask(
    __name__,
    template_folder=os.path.join(os.path.dirname(__file__), "..", "templates"),
    static_folder=None,
)

# 全局组件
storage = None
nginx_parser = None
auth_parser = None
classifier = None
file_monitor = None
fingerprint_parser = None
collector_running = False


def init_components():
    """初始化所有组件"""
    global storage, nginx_parser, auth_parser, classifier, file_monitor, fingerprint_parser

    storage = AttackStorage(CONFIG["db_path"])
    nginx_parser = NginxLogParser(CONFIG["nginx_log"])
    auth_parser = AuthLogParser(CONFIG["auth_log"])
    classifier = AttackClassifier()
    fingerprint_parser = FingerprintParser()

    # 初始化文件监控
    watch_paths = CONFIG["watch_paths"]
    file_monitor = FileMonitor(storage=storage, watch_paths=watch_paths)

    print(f"[Dashboard] 数据库: {CONFIG['db_path']}")
    print(f"[Dashboard] Nginx日志: {CONFIG['nginx_log']}")
    print(f"[Dashboard] Auth日志: {CONFIG['auth_log']}")
    print(f"[Dashboard] 文件监控: {watch_paths or '默认路径'}")


def collect_loop():
    """后台日志收集循环"""
    global collector_running
    collector_running = True
    consecutive_errors = 0

    print("[Collector] 日志收集已启动")

    while collector_running:
        try:
            batch = []

            # 解析 Nginx 日志
            for line in nginx_parser.get_new_lines():
                event = nginx_parser.parse_line(line)
                if event:
                    event = classifier.classify(event)
                    batch.append(event)

            # 解析 Auth 日志
            for line in auth_parser.get_new_lines():
                event = auth_parser.parse_line(line)
                if event:
                    event = classifier.classify(event)
                    batch.append(event)

            # 批量写入数据库
            if batch:
                count = storage.insert_attacks_batch(batch)
                if count > 0:
                    print(f"[Collector] 新增 {count} 条攻击记录")

            consecutive_errors = 0
            time.sleep(CONFIG["scan_interval"])

        except Exception as e:
            consecutive_errors += 1
            print(f"[Collector] 错误: {e} (连续 {consecutive_errors} 次)")
            if consecutive_errors > 10:
                time.sleep(30)  # 连续出错，等待更长时间
            else:
                time.sleep(5)


# ===== 路由 =====

@app.route("/")
def index():
    """主仪表板页面"""
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    """攻击统计数据 API"""
    if not storage:
        return jsonify({"error": "存储未初始化"}), 503

    stats = storage.get_attack_stats(hours=24)
    total = storage.get_total_count()
    stats["total_attacks"] = total
    return jsonify(stats)


@app.route("/api/recent")
def api_recent():
    """最近攻击记录 API（含指纹）"""
    limit = min(int(request.args.get("limit", 100)), 500)
    if not storage:
        return jsonify([]), 503
    attacks = storage.get_recent_attacks(limit=limit)

    # 批量解析指纹
    if fingerprint_parser and attacks:
        attacks = fingerprint_parser.batch_parse(attacks)

    return jsonify(attacks)


@app.route("/api/top-attackers")
def api_top_attackers():
    """TOP 攻击者 API"""
    limit = min(int(request.args.get("limit", 20)), 100)
    if not storage:
        return jsonify([]), 503
    attackers = storage.get_top_attackers(limit=limit)
    return jsonify(attackers)


@app.route("/api/file-events")
def api_file_events():
    """文件访问事件 API"""
    limit = min(int(request.args.get("limit", 50)), 200)

    # 优先从内存获取实时数据
    if file_monitor:
        events = file_monitor.get_recent_events(limit=limit)
        return jsonify(events)

    # 回退到数据库
    if storage:
        events = storage.get_recent_file_events(limit=limit)
        return jsonify(events)

    return jsonify([]), 503


@app.route("/api/file-stats")
def api_file_stats():
    """文件监控统计 API"""
    if file_monitor:
        return jsonify(file_monitor.get_stats())

    if storage:
        return jsonify(storage.get_file_event_stats(hours=24))

    return jsonify({"error": "文件监控未启用"}), 503


@app.route("/api/fingerprint/<path:user_agent>")
def api_fingerprint(user_agent):
    """单次指纹解析 API（用于调试）"""
    if not fingerprint_parser:
        return jsonify({"error": "指纹解析器未初始化"}), 503

    # URL 解码
    from urllib.parse import unquote
    ua = unquote(user_agent)
    ip = request.args.get("ip", "")

    fp = fingerprint_parser.parse(ua, ip)
    return jsonify(fp)


@app.route("/api/health")
def api_health():
    """健康检查"""
    return jsonify({
        "status": "ok",
        "uptime": time.time() - app.start_time if hasattr(app, "start_time") else 0,
        "collector_running": collector_running,
        "file_monitor_running": file_monitor._running if file_monitor else False,
        "total_records": storage.get_total_count() if storage else 0,
        "fingerprint_cache": fingerprint_parser.get_cache_stats() if fingerprint_parser else {},
    })


# ===== 访客信息 API =====

def get_client_ip():
    """获取客户端真实 IP，按优先级检查各种代理头"""
    headers = request.headers
    # Cloudflare
    cf_ip = headers.get("CF-Connecting-IP", "")
    if cf_ip:
        return cf_ip, "cloudflare"
    # 标准 proxy 头
    for h in ["X-Forwarded-For", "X-Real-IP"]:
        val = headers.get(h, "")
        if val:
            ip = val.split(",")[0].strip()
            if ip:
                return ip, h
    # 直连
    return request.remote_addr, "direct"


def get_geo_info(ip):
    """通过 ip-api.com 获取 IP 地理位置（免费，无需 key）"""
    try:
        url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,hosting,proxy"
        with urlopen(url, timeout=5) as resp:
            data = json.loads(resp.read().decode())
        if data.get("status") == "success":
            return {
                "country": data.get("country", ""),
                "countryCode": data.get("countryCode", ""),
                "regionName": data.get("regionName", ""),
                "city": data.get("city", ""),
                "zip": data.get("zip", ""),
                "lat": data.get("lat", 0),
                "lon": data.get("lon", 0),
                "timezone": data.get("timezone", ""),
                "isp": data.get("isp", ""),
                "org": data.get("org", ""),
                "as": data.get("as", ""),
                "hosting": data.get("hosting", False),
                "proxy": data.get("proxy", False),
            }
    except Exception as e:
        print(f"[Geo] 查询失败: {e}")
    return {}


@app.route("/api/visitor-info")
def api_visitor_info():
    """返回访问者的完整信息：IP、地理位置、HTTP头、代理检测"""
    ip, source = get_client_ip()

    # 获取地理位置
    geo = get_geo_info(ip)

    # 收集 HTTP 头信息
    headers = {
        "x_forwarded_for": request.headers.get("X-Forwarded-For", ""),
        "x_real_ip": request.headers.get("X-Real-IP", ""),
        "cf_connecting_ip": request.headers.get("CF-Connecting-IP", ""),
        "via": request.headers.get("Via", ""),
        "cf_ray": request.headers.get("CF-Ray", ""),
        "cf_ipcountry": request.headers.get("CF-IPCountry", ""),
        "accept_language": request.headers.get("Accept-Language", ""),
        "user_agent": request.headers.get("User-Agent", ""),
    }

    return jsonify({
        "ip": ip,
        "ip_source": source,
        "geo": geo,
        "proxy": geo.get("proxy", False),
        "vpn": False,  # ip-api 免费版不提供 VPN 检测
        "datacenter": geo.get("hosting", False),
        "hosting": geo.get("hosting", False),
        "headers": headers,
        "method": request.method,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/traceroute")
def api_traceroute():
    """执行 traceroute 到客户端 IP 或指定目标"""
    target = request.args.get("target", "")

    if not target:
        # 默认追踪到客户端 IP
        ip, _ = get_client_ip()
        target = ip

    hops = []
    try:
        # 使用 traceroute (macOS/Linux)
        result = subprocess.run(
            ["traceroute", "-n", "-w", "2", "-q", "1", "-m", "25", target],
            capture_output=True, text=True, timeout=30
        )
        output = result.stdout

        # 解析 traceroute 输出
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                continue
            # 格式: 1 192.168.1.1 0.123 ms
            m = re.match(r"(\d+)\s+(?:(\S+)\s+)?(\S+)\s+([\d.]+)\s*ms", line)
            if m:
                hop_num = int(m.group(1))
                hostname = m.group(2) or ""
                ip_addr = m.group(3)
                ms_str = m.group(4)

                if ip_addr == "*":
                    hops.append({"hop": hop_num, "ip": "", "hostname": "", "ms": 0, "timeout": True})
                else:
                    try:
                        ms = float(ms_str)
                        hops.append({"hop": hop_num, "ip": ip_addr, "hostname": hostname, "ms": round(ms, 2), "timeout": False})
                    except ValueError:
                        hops.append({"hop": hop_num, "ip": ip_addr, "hostname": hostname, "ms": 0, "timeout": False})

    except FileNotFoundError:
        return jsonify({"error": "traceroute 命令不可用", "hops": []})
    except subprocess.TimeoutExpired:
        return jsonify({"error": "traceroute 超时", "hops": hops})
    except Exception as e:
        return jsonify({"error": str(e), "hops": []})

    return jsonify({"target": target, "hops": hops})


def main():
    """启动服务"""
    print("=" * 60)
    print("  CyberStroll Top - 靶机监控仪表板")
    print("=" * 60)

    # 初始化组件
    init_components()

    # 启动后台收集线程
    collector_thread = threading.Thread(target=collect_loop, daemon=True)
    collector_thread.start()

    # 启动文件监控
    if file_monitor:
        try:
            file_monitor.start()
        except Exception as e:
            print(f"[FileMonitor] 启动失败: {e}")

    # 记录启动时间
    app.start_time = time.time()

    # 启动 Web 服务
    port = CONFIG["dashboard_port"]
    print(f"\n[Dashboard] 服务启动在 http://0.0.0.0:{port}")
    print(f"[Dashboard] 按 Ctrl+C 停止\n")

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False,
        threaded=True,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
