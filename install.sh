#!/usr/bin/env bash
# ========================================================
# SRC 资产检测站 (SRC Assets Monitor) - Linux 生产环境一键部署脚本
# 支持系统: Ubuntu 20.04+, Debian 11+, CentOS 8+, Rocky/Alma Linux
# ========================================================

set -e

GREEN="\033[32m"
RED="\033[31m"
YELLOW="\033[33m"
BLUE="\033[34m"
PLAIN="\033[0m"

echo -e "${BLUE}========================================================${PLAIN}"
echo -e "${GREEN}   SRC 资产检测站 (SRC Assets Monitor) 一键自动化部署   ${PLAIN}"
echo -e "${BLUE}========================================================${PLAIN}"

# 1. 检查 root 权限
if [ "$(id -u)" != "0" ]; then
    echo -e "${RED}错误: 必须使用 root 权限运行此脚本！(可使用 sudo ./install.sh)${PLAIN}"
    exit 1
fi

PROJECT_DIR=$(cd "$(dirname "$0")"; pwd)
cd "$PROJECT_DIR"

echo -e "${YELLOW}[1/5] 检测系统环境与基础依赖包...${PLAIN}"
if [ -f /etc/debian_version ]; then
    apt-get update -y
    apt-get install -y curl git zip unzip software-properties-common
    # 安装 PHP 8.1/8.2 核心与扩展
    apt-get install -y php-cli php-fpm php-mysql php-sqlite3 php-curl php-mbstring php-xml php-openssl php-sockets || true
elif [ -f /etc/redhat-release ]; then
    dnf install -y epel-release || yum install -y epel-release
    dnf install -y curl git zip unzip php-cli php-fpm php-mysqlnd php-curl php-mbstring php-xml php-sockets || true
fi

# 2. 检查 PHP 运行时
if ! command -v php >/dev/null 2>&1; then
    echo -e "${RED}错误: 未能自动检测到 PHP 命令行环境，请手动安装 PHP 8.1 或更高版本后重试。${PLAIN}"
    exit 1
fi

PHP_VER=$(php -r 'echo PHP_VERSION;')
echo -e "${GREEN}检测到 PHP 运行时版本: ${PHP_VER}${PLAIN}"

# 3. 初始化目录权限
echo -e "${YELLOW}[2/5] 配置文件与运行时存储目录权限...${PLAIN}"
mkdir -p runtime public/uploads

if id "www-data" >/dev/null 2>&1; then
    chown -R www-data:www-data runtime public/uploads
elif id "nginx" >/dev/null 2>&1; then
    chown -R nginx:nginx runtime public/uploads
fi
chmod -R 775 runtime public/uploads

# 4. 生成 .env 基础配置
echo -e "${YELLOW}[3/5] 检查系统配置文件 .env ...${PLAIN}"
if [ ! -f .env ]; then
    cp .env.example .env
    # 随机生成 APP_KEY
    RAND_KEY=$(php -r 'echo base64_encode(random_bytes(32));')
    sed -i "s|APP_KEY=.*|APP_KEY=base64:${RAND_KEY}|g" .env
    echo -e "${GREEN}已基于模板生成全新 .env，并注入高强度应用安全密钥${PLAIN}"
fi

# 5. 部署完成提示与快速启动选择
echo -e "${BLUE}========================================================${PLAIN}"
echo -e "${GREEN}恭喜！SRC 资产检测站基础部署已就绪！${PLAIN}"
echo -e "${YELLOW}运行模式选择:${PLAIN}"
echo -e "  1. 生产环境部署 (Nginx + PHP-FPM):"
echo -e "     - 将 Nginx 网站根目录 (root) 指向: ${GREEN}${PROJECT_DIR}/public${PLAIN}"
echo -e "     - 确保设置伪静态规则: try_files \$uri \$uri/ /index.php?\$query_string;"
echo -e "  2. 极速临时运行测试 (PHP 内置服务器):"
echo -e "     执行命令: ${GREEN}php -S 0.0.0.0:8000 -t public${PLAIN}"
echo -e "     随后在浏览器中访问: ${GREEN}http://<服务器IP>:8000/${PLAIN} 进入安装向导"
echo -e "  3. 配置定时任务 (Crontab):"
echo -e "     echo '* * * * * cd ${PROJECT_DIR} && php app/Console/cron.php >> /dev/null 2>&1' | crontab -"
echo -e "${BLUE}========================================================${PLAIN}"
