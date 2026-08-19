#!/bin/bash
# CyberStroll Top 一键安装脚本
# 用法: sudo bash scripts/install.sh

set -e

echo "============================================"
echo "  CyberStroll Top - 靶机初始化安装"
echo "============================================"

# 检查 root 权限
if [ "$EUID" -ne 0 ]; then
    echo "❌ 请使用 sudo 运行: sudo bash $0"
    exit 1
fi

# 配置变量
INSTALL_DIR="/opt/cyberstroll"
SERVICE_NAME="cyberstroll"
DASHBOARD_PORT=8090
NGINX_PORT=80

echo ""
echo "📦 安装依赖..."
apt-get update -qq
apt-get install -y -qq python3 python3-pip python3-venv nginx > /dev/null 2>&1

# 创建虚拟环境
echo "🐍 创建 Python 环境..."
python3 -m venv "$INSTALL_DIR/venv"
source "$INSTALL_DIR/venv/bin/activate"
pip install --quiet flask 2>/dev/null || true

deactivate

# 复制项目文件
echo "📁 部署项目文件..."
mkdir -p "$INSTALL_DIR"/{data,collector,dashboard,honeypot,templates}

# 获取脚本所在目录（支持从 git clone 或本地运行）
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

if [ -f "$SCRIPT_DIR/dashboard/server.py" ]; then
    # 从源码目录复制
    cp -r "$SCRIPT_DIR/collector/"* "$INSTALL_DIR/collector/"
    cp -r "$SCRIPT_DIR/dashboard/"* "$INSTALL_DIR/dashboard/"
    cp -r "$SCRIPT_DIR/templates/"* "$INSTALL_DIR/templates/"
    echo "   从 $SCRIPT_DIR 复制文件"
else
    echo "⚠️  未找到源码，请确保在项目根目录运行此脚本"
fi

# 设置权限
chown -R www-data:www-data "$INSTALL_DIR"
chmod -R 755 "$INSTALL_DIR"

# 创建 systemd 服务
echo "⚙️  配置系统服务..."
cat > "/etc/systemd/system/${SERVICE_NAME}.service" << EOF
[Unit]
Description=CyberStroll Top Honeypot Dashboard
After=network.target nginx.service
Wants=nginx.service

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=${INSTALL_DIR}
Environment="PATH=${INSTALL_DIR}/venv/bin:/usr/bin:/bin"
Environment="DASHBOARD_PORT=${DASHBOARD_PORT}"
Environment="DB_PATH=${INSTALL_DIR}/data/attacks.db"
Environment="NGINX_LOG=/var/log/nginx/access.log"
Environment="AUTH_LOG=/var/log/auth.log"
ExecStart=${INSTALL_DIR}/venv/bin/python3 ${INSTALL_DIR}/dashboard/server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 配置 nginx 反代
echo "🌐 配置 Nginx..."
cat > "/etc/sites-available/cyberstroll-dashboard" << 'NGINXEOF'
server {
    listen ${DASHBOARD_PORT};
    listen [::]:${DASHBOARD_PORT};

    location / {
        proxy_pass http://127.0.0.1:${DASHBOARD_PORT};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket 支持 (如果需要)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
NGINXEOF

# 启用服务
systemctl daemon-reload
systemctl enable "${SERVICE_NAME}"
systemctl start "${SERVICE_NAME}"

# 等待启动
sleep 2

# 验证
echo ""
echo "✅ 安装完成！"
echo ""
echo "============================================"
echo "  CyberStroll Top 已部署"
echo "============================================"
echo ""
echo "仪表板地址: http://$(hostname -I | awk '{print $1}'):${DASHBOARD_PORT}"
echo ""
echo "常用命令:"
echo "  查看状态:  systemctl status ${SERVICE_NAME}"
echo "  查看日志:  journalctl -u ${SERVICE_NAME} -f"
echo "  重启服务:  systemctl restart ${SERVICE_NAME}"
echo "  停止服务:  systemctl stop ${SERVICE_NAME}"
echo ""
echo "数据存储: ${INSTALL_DIR}/data/attacks.db"
echo ""
