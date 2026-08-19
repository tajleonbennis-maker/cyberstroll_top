#!/bin/bash
# CyberStroll Top 更新脚本
# 用法: sudo bash scripts/update.sh

set -e

SERVICE_NAME="cyberstroll"
INSTALL_DIR="/opt/cyberstroll"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "🔄 更新 CyberStroll Top..."

# 停止服务
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true

# 备份数据库
if [ -f "${INSTALL_DIR}/data/attacks.db" ]; then
    cp "${INSTALL_DIR}/data/attacks.db" "${INSTALL_DIR}/data/attacks.db.bak"
    echo "✓ 数据库已备份"
fi

# 更新文件
if [ -f "$SCRIPT_DIR/dashboard/server.py" ]; then
    cp -r "$SCRIPT_DIR/collector/"* "$INSTALL_DIR/collector/"
    cp -r "$SCRIPT_DIR/dashboard/"* "$INSTALL_DIR/dashboard/"
    cp -r "$SCRIPT_DIR/templates/"* "$INSTALL_DIR/templates/"
    echo "✓ 文件已更新"
else
    echo "⚠️  未找到源码目录"
fi

# 重启服务
systemctl start "${SERVICE_NAME}"
sleep 2

# 验证
if systemctl is-active --quiet "${SERVICE_NAME}"; then
    echo "✅ 更新完成，服务运行中"
    systemctl status "${SERVICE_NAME}" --no-pager | head -5
else
    echo "❌ 服务启动失败，请检查日志: journalctl -u ${SERVICE_NAME}"
fi
