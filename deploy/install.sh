#!/bin/bash
set -e

# === ZenProxy 一键部署脚本 ===
# 用法: 把 deploy/ 目录上传到服务器后执行此脚本
# bash install.sh

APP_NAME="zenproxy"
INSTALL_DIR="/opt/zenproxy"
SERVICE_FILE="/etc/systemd/system/zenproxy.service"
DOMAIN="proxy.zenapi.top"

echo "=== ZenProxy 部署脚本 ==="

# 检查 root
if [ "$EUID" -ne 0 ]; then
  echo "请用 root 运行: sudo bash install.sh"
  exit 1
fi

# 停止旧服务（如果存在）
if systemctl is-active --quiet zenproxy 2>/dev/null; then
  echo "[1/6] 停止旧服务..."
  systemctl stop zenproxy
else
  echo "[1/6] 无旧服务运行"
fi

# 创建目录
echo "[2/6] 安装文件到 ${INSTALL_DIR}..."
mkdir -p ${INSTALL_DIR}/data
cp -f zenproxy ${INSTALL_DIR}/zenproxy
if [ ! -f "${INSTALL_DIR}/config.toml" ]; then
  cp -f config.toml.example ${INSTALL_DIR}/config.toml
fi
chmod +x ${INSTALL_DIR}/zenproxy

# 创建 systemd 服务
echo "[3/6] 创建 systemd 服务..."
cat > ${SERVICE_FILE} << 'EOF'
[Unit]
Description=ZenProxy Service
After=network.target

[Service]
Type=simple
WorkingDirectory=/opt/zenproxy
ExecStart=/opt/zenproxy/zenproxy
Restart=always
RestartSec=5
Environment=RUST_LOG=zenproxy=info

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable zenproxy

# 配置 nginx 反向代理（如果安装了 nginx）
if command -v nginx &>/dev/null; then
  echo "[4/6] 配置 Nginx 反向代理..."
  cat > /etc/nginx/sites-available/zenproxy << NGINXEOF
server {
    listen 80;
    server_name ${DOMAIN};

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
NGINXEOF

  # 启用站点
  ln -sf /etc/nginx/sites-available/zenproxy /etc/nginx/sites-enabled/zenproxy
  nginx -t && systemctl reload nginx
  echo "  Nginx 已配置: ${DOMAIN} -> 127.0.0.1:3000"

  # 申请 SSL（如果安装了 certbot）
  if command -v certbot &>/dev/null; then
    echo "[5/6] 申请 SSL 证书..."
    certbot --nginx -d ${DOMAIN} --non-interactive --agree-tos --register-unsafely-without-email || echo "  SSL 申请失败，请手动运行: certbot --nginx -d ${DOMAIN}"
  else
    echo "[5/6] 未安装 certbot，跳过 SSL。安装后运行: certbot --nginx -d ${DOMAIN}"
  fi
else
  echo "[4/6] 未安装 Nginx，跳过反代配置"
  echo "[5/6] 跳过 SSL"
fi

# 启动服务
echo "[6/6] 启动 ZenProxy..."
systemctl start zenproxy

echo ""
echo "=== 部署完成 ==="
echo "  安装目录: ${INSTALL_DIR}"
echo "  配置文件: ${INSTALL_DIR}/config.toml"
echo "  数据目录: ${INSTALL_DIR}/data"
echo ""
echo "  常用命令:"
echo "    查看状态: systemctl status zenproxy"
echo "    查看日志: journalctl -u zenproxy -f"
echo "    重启服务: systemctl restart zenproxy"
echo "    编辑配置: nano ${INSTALL_DIR}/config.toml"
echo ""
echo "  !! 重要: 请编辑 config.toml 填写 OAuth 配置 !!"
echo "    client_id 和 client_secret 从 https://connect.linux.do 获取"
echo ""
