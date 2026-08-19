# CyberStroll Top - 攻防演练靶机

> VPS 靶机初始化代码，开机自动展示攻击数据仪表板

## 架构

```
cyberstroll_top/
├── README.md              # 本文件
├── docker-compose.yml     # 一键部署（可选）
├── requirements.txt       # Python 依赖
├── collector/             # 攻击数据收集器
│   ├── __init__.py
│   ├── log_parser.py      # 日志解析（nginx/auth/syslog）
│   ├── attack_classifier.py # 攻击类型分类
│   └── storage.py         # 数据存储（JSON/SQLite）
├── honeypot/              # 蜜罐服务
│   ├── __init__.py
│   ├── ssh_honeypot.py    # 伪造 SSH 服务
│   └── http_honeypot.py   # 伪造 HTTP 陷阱
├── dashboard/             # 可视化仪表板
│   ├── server.py          # Flask Web 服务
│   ├── api.py             # 数据 API
│   └── static/            # CSS/JS
├── templates/             # HTML 模板
│   └── index.html         # 主仪表板页面
└── scripts/               # 系统服务脚本
    ├── install.sh         # 一键安装
    ├── cyberstroll.service # systemd 服务
    └── update.sh          # 更新脚本
```

## 功能特性

### 🎯 攻击检测
- **端口扫描检测**：识别 SYN scan、CONNECT scan、UDP scan
- **暴力破解检测**：SSH/FTP/HTTP 暴力破解尝试
- **Web 攻击检测**：SQL 注入、XSS、路径遍历、扫描器指纹
- **蜜罐诱捕**：伪造 SSH/HTTP 服务，记录攻击者行为

### 📊 实时仪表板
- **世界地图**：攻击来源地理位置分布
- **攻击时间线**：实时攻击事件流
- **TOP 攻击 IP**：最活跃的攻击者排行
- **攻击类型统计**：饼图/柱状图展示各类攻击占比
- **攻击详情**：每次攻击的完整 payload 和上下文

### 🔧 自动化
- 开机自启动（systemd）
- 自动更新攻击签名库
- 数据持久化，重启不丢失
- 低资源占用（<50MB 内存）

## 快速开始

```bash
# 1. 克隆仓库
git clone https://github.com/tajleonbennis-maker/cyberstroll_top.git
cd cyberstroll_top

# 2. 一键安装
sudo bash scripts/install.sh

# 3. 访问仪表板
# http://<你的IP>:8090
```

## 手动部署

```bash
# 安装依赖
pip3 install -r requirements.txt

# 启动服务
python3 dashboard/server.py

# 或使用 systemd
sudo cp scripts/cyberstroll.service /etc/systemd/system/
sudo systemctl enable --now cyberstroll
```

## 配置说明

配置文件：`/opt/cyberstroll/config.json`

```json
{
  "dashboard_port": 8090,
  "honeypot": {
    "ssh_enabled": true,
    "ssh_port": 2222,
    "http_enabled": true,
    "http_port": 8088
  },
  "collector": {
    "nginx_log": "/var/log/nginx/access.log",
    "auth_log": "/var/log/auth.log",
    "scan_interval": 5
  }
}
```

## 攻击分类规则

| 类型 | 特征 | 危险等级 |
|------|------|----------|
| 端口扫描 | 短时间内多端口连接 | 🟡 中 |
| SSH 暴力破解 | 多次认证失败 | 🔴 高 |
| SQL 注入 | UNION/SELECT/INSERT 等 | 🔴 高 |
| XSS 攻击 | script/onerror 等 | 🔴 高 |
| 路径遍历 | ../\.\./etc/ | 🟠 中 |
| 扫描器指纹 | Nmap/Masscan/DirBuster | 🟢 低 |
| 敏感文件访问 | .env/.git/wp-admin | 🟡 中 |

## 技术栈

- **后端**：Python 3 + Flask + SQLite
- **前端**：原生 HTML/CSS/JS + Chart.js + Leaflet.js
- **数据收集**：tail -f 日志 + 正则匹配
- **蜜罐**：asyncio + socket 编程
- **部署**：systemd + nginx 反代

## License

MIT
