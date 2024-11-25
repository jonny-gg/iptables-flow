#!/bin/bash

# 设置错误时退出
set -e

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

# 日志函数
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查root权限
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root"
    exit 1
fi

# 创建日志目录
log_info "Creating log directory..."
mkdir -p /logs/iptables
chmod 755 /logs/iptables

# 创建logrotate配置
log_info "Creating logrotate configuration..."
cat > /etc/logrotate.d/traffic-monitor << 'EOF'
/logs/iptables/* {
    daily
    rotate 7
    dateext
    dateformat -%Y%m%d
    missingok
    compress
    delaycompress
    notifempty
    create 0644 root root
}
EOF

# 测试logrotate配置
log_info "Testing logrotate configuration..."
if ! logrotate -d /etc/logrotate.d/traffic-monitor; then
    log_error "Logrotate configuration test failed"
    exit 1
fi

log_info "Setup completed successfully!"
log_info "Logs will be rotated daily and kept for 7 days in /logs/iptables/"