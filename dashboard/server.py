"""CyberStroll Top - Dashboard Flask 服务器"""
import os
import sys
import json
import time
import threading
from datetime import datetime, timezone, timedelta

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, render_template, jsonify, send_from_directory

# 导入收集器模块
from collector.log_parser import NginxLogParser, AuthLogParser
from collector.attack_classifier import AttackClassifier
from collector.storage import AttackStorage

# 配置
CONFIG = {
    "dashboard_port": int(os.environ.get("DASHBOARD_PORT", 8090)),
    "nginx_log": os.environ.get("NGINX_LOG", "/var/log/nginx/access.log"),
    "auth_log": os.environ.get("AUTH_LOG", "/var/log/auth.log"),
    "db_path": os.environ.get("DB_PATH", "/opt/cyberstroll/data/attacks.db"),
    "scan_interval": int(os.environ.get("SCAN_INTERVAL", 5)),  # 秒
    "honeypot_ssh_port": int(os.environ.get("HONEYPOT_SSH_PORT", 2222)),
    "honeypot_http_port": int(os.environ.get("HONEYPOT_HTTP_PORT", 8088)),
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
collector_running = False


def init_components():
    """初始化所有组件"""
    global storage, nginx_parser, auth_parser, classifier

    storage = AttackStorage(CONFIG["db_path"])
    nginx_parser = NginxLogParser(CONFIG["nginx_log"])
    auth_parser = AuthLogParser(CONFIG["auth_log"])
    classifier = AttackClassifier()

    print(f"[Dashboard] 数据库: {CONFIG['db_path']}")
    print(f"[Dashboard] Nginx日志: {CONFIG['nginx_log']}")
    print(f"[Dashboard] Auth日志: {CONFIG['auth_log']}")


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
    """最近攻击记录 API"""
    limit = min(int(request.args.get("limit", 100)), 500) if hasattr(request, 'args') else 100
    if not storage:
        return jsonify([]), 503
    attacks = storage.get_recent_attacks(limit=limit)
    return jsonify(attacks)


@app.route("/api/top-attackers")
def api_top_attackers():
    """TOP 攻击者 API"""
    limit = min(int(request.args.get("limit", 20)), 100) if hasattr(request, 'args') else 20
    if not storage:
        return jsonify([]), 503
    attackers = storage.get_top_attackers(limit=limit)
    return jsonify(attackers)


@app.route("/api/health")
def api_health():
    """健康检查"""
    return jsonify({
        "status": "ok",
        "uptime": time.time() - app.start_time if hasattr(app, "start_time") else 0,
        "collector_running": collector_running,
        "total_records": storage.get_total_count() if storage else 0,
    })


# 兼容 Flask < 2.x 的 request 引入方式
try:
    from flask import request
except ImportError:
    pass


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
