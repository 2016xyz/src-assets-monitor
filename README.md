# SRC 资产检测站 (SRC Assets Monitor)

> 专为企业安全应急团队、SRC 漏洞挖掘白帽与资产测绘工程师打造的高性能全景子域名资产监控平台。
> 支持**8+ 被动多源并发采集**、**DoH over 代理防封调度**、**泛解析 (Wildcard) 智能清洗**、**CNAME 链追踪与云存储接管风险检测**、**自动资产名称识别与内联别名标注**、以及**多渠道告警聚合推送**。

---

## 一、系统核心架构与特性

### 1. 为什么选择 DoH over 代理穿透？
传统 DNS 枚举直接利用 UDP 53 端口向目标权威 NS 频繁发起查询，极易触发目标安全网关拦截或运营商限速；且市面上绝大部分企业 HTTP/SOCKS5 代理不支持 UDP。
本平台采用 **DoH (DNS over HTTPS) 穿透代理池** 技术方案：

```text
[检测引擎] ➔ [本地代理调度器 (Round-Robin/Weighted)] ➔ [SOCKS5/HTTP 代理隧道] ➔ [公共 DoH (Google/Cloudflare)] ➔ 返回解析 JSON
```

- **全协议穿透**：原生支持 `http`、`https`、`socks5` 以及支持远程 DNS 解析的 `socks5h` 代理协议；
- **防污染防旁路**：避开本地运营商 DNS 劫持，结果真实纯净；
- **多层防封机制**：滑动窗口令牌桶限速（默认 120 次/分/节点）+ 连续 3 次失败动态熔断 + 150~300ms 随机物理抖动。

### 2. 八大多维资产发现与检测机制
1. **多源被动并发采集**：聚合 `crt.sh`、`CertSpotter`、`HackerTarget`、`AlienVault OTX`、`Wayback Machine`、`AnubisDB`、`RapidDNS`、`urlscan.io` 以及主域名 TLS SAN 证书扩展；
2. **开放解析器池轮询**：预置公共开放 DNS 解析器池（Cloudflare/Google/Quad9/AliDNS/DNSPod/114DNS 等），爆破前自动可用性探针，分散流量压力；
3. **泛解析 (Wildcard) 识别与过滤**：随机探针识别泛解析 IP/CNAME 特征黑名单，爆破时自动比对清洗伪造资产；
4. **CNAME 链与云存储接管检测**：递归追踪 CNAME 每一跳（限制深度 ≤5），识别 AWS S3、GitHub Pages、Vercel、Netlify 等第三方托管平台，标记悬挂接管风险；
5. **DNS 区域传送 (AXFR)**：探测目标权威 NS 是否存在配置疏漏，高敏操作默认关闭，需显式开启；
6. **代码泄露搜寻 (GitHub Dorks)**：自动检索硬编码的子域名与 API 端点，通过 FQDN 正则与合法性校验后入库；
7. **JavaScript 与 Source Map 挖掘**：深度提取存活 Web 资产引用脚本中的隐藏域名，解析 `.map` 文件的 `sourcesContent`；
8. **资产名称动态识别**：按 `alias ➔ http_title ➔ http_server ➔ cname ➔ ptr ➔ hostname` 优先级链智能提取中文资产名称，支持列表内联编辑与全渠道告警展示。

---

## 二、全平台详细安装与搭建教程

系统支持 **Docker 容器编排 (推荐生产)**、**Linux 原生**、**Windows 本地**、**宝塔面板** 四种部署形态。

---

### 方案 3：Docker & Docker Compose 一键启动 (全平台通用 · 生产推荐)

完全环境隔离，无需在宿主机额外配置 PHP、MySQL、Nginx 或 Redis。

#### 3.1 前置环境安装 (若服务器尚未安装 Docker)

- **Ubuntu / Debian**：
  ```bash
  # 移除旧版本并安装官方 Docker 引擎
  sudo apt-get update
  sudo apt-get install -y ca-certificates curl gnupg
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  ```
- **CentOS / RHEL 8+**：
  ```bash
  sudo yum install -y yum-utils
  sudo yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
  sudo yum install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  sudo systemctl start docker && sudo systemctl enable docker
  ```

#### 3.2 完整详细启动命令 (复制即可执行)

```bash
# 步骤 1: 克隆项目源码到服务器
git clone https://github.com/2016xyz/src-assets-monitor.git
cd src-assets-monitor

# 步骤 2: 准备配置文件与运行时权限
cp .env.example .env
mkdir -p runtime public/uploads
chmod -R 777 runtime public/uploads

# 步骤 3: 一键构建镜像并启动全部容器 (app + cron + nginx + mysql + redis)
docker compose up -d --build
```

#### 3.3 查看运行状态与验证

```bash
# 查看所有容器健康状态 (确认全部处于 Up / healthy 状态)
docker compose ps

# 预期输出:
# NAME                IMAGE                 COMMAND                  SERVICE   STATUS                    PORTS
# src_monitor_app     src-assets-monitor-app "docker-php-entrypoi…"   app       running                   9000/tcp
# src_monitor_cron    src-assets-monitor-cron "sh -c 'while true; …"   cron      running                   
# src_monitor_mysql   mysql:8.0             "docker-entrypoint.s…"   mysql     running (healthy)         0.0.0.0:3306->3306/tcp
# src_monitor_nginx   nginx:alpine          "/docker-entrypoint.…"   nginx     running                   0.0.0.0:8080->80/tcp
# src_monitor_redis   redis:7-alpine        "docker-entrypoint.s…"   redis     running                   6379/tcp
```

#### 3.4 浏览器完成首次安装向导配置

在浏览器中打开：
```text
http://<您的服务器IP>:8080/
```
系统将自动进入 5 步初始化向导，在 **步骤 2「数据库配置」** 中填写：
- **主机地址**：填写容器服务名 **`mysql`**（注意不要填 127.0.0.1）
- **端口**：**`3306`**
- **数据库名**：**`src_monitor`**
- **用户名**：**`root`**
- **密码**：**`rootpassword`**
- 点击「测试数据库连接」➔ 测试通过后点击「下一步」自动完成建表迁移！

#### 3.5 常用维护与运维命令清单

```bash
# 查看业务实时流水日志 (查看检测任务调度)
docker compose logs -f cron

# 查看 PHP-FPM 与 Web 访问日志
docker compose logs -f app
docker compose logs -f nginx

# 重启全部服务
docker compose restart

# 进入后端容器 CLI 环境 (执行手动调试命令)
docker compose exec app sh

# 停止并保留数据库数据
docker compose stop

# 完全停止并移除容器 (数据保留在 Docker 数据卷 mysql_data 中)
docker compose down
```

---

### 方案 1：Linux 生产环境原生搭建 (Ubuntu / Debian / CentOS)

#### 1.1 一键自动化安装 (最简方式)
```bash
# 克隆仓库
git clone https://github.com/2016xyz/src-assets-monitor.git
cd src-assets-monitor

# 授予执行权限并运行一键安装脚本
chmod +x install.sh
sudo ./install.sh
```

#### 1.2 手动配置步骤
1. **安装环境依赖**：
   - Ubuntu / Debian：
     ```bash
     sudo apt update && sudo apt install -y php-cli php-fpm php-mysql php-sqlite3 php-curl php-mbstring php-xml php-openssl php-sockets nginx
     ```
   - CentOS / RHEL 8+：
     ```bash
     sudo dnf install -y epel-release && sudo dnf install -y php-cli php-fpm php-mysqlnd php-curl php-mbstring php-xml php-sockets nginx
     ```
2. **初始化配置与目录权限**：
   ```bash
   cp .env.example .env
   mkdir -p runtime public/uploads
   sudo chown -R www-data:www-data runtime public/uploads  # CentOS 为 nginx:nginx
   sudo chmod -R 775 runtime public/uploads
   ```
3. **配置 Nginx 虚拟主机**（`/etc/nginx/conf.d/src_monitor.conf`）：
   ```nginx
   server {
       listen 80;
       server_name monitor.yourdomain.com; # 您的域名或服务器IP
       root /path/to/src-assets-monitor/public;
       index index.html index.php;

       client_max_body_size 20M;

       location / {
           try_files $uri $uri/ /index.html;
       }

       location ^~ /api/ {
           try_files $uri $uri/ /index.php?$query_string;
       }

       location ~ \.php$ {
           fastcgi_pass unix:/var/run/php/php8.2-fpm.sock; # 或 127.0.0.1:9000
           fastcgi_index index.php;
           fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
           include fastcgi_params;
           fastcgi_read_timeout 180;
       }

       location ~ /\.(env|git|lock) {
           deny all;
       }
   }
   ```
   重启 Nginx：`sudo systemctl restart nginx`。
4. **配置自动化巡检定时任务 (Crontab)**：
   ```bash
   crontab -e
   # 添加以下行，每分钟自动驱动资产探测、泛解析清洗与代理健康巡检
   * * * * * cd /path/to/src-assets-monitor && php app/Console/cron.php >> /dev/null 2>&1
   ```

---

### 方案 2：Windows 本地快速运行 (开箱即用)

适用于开发调试、内网或 Windows Server 运维人员。

1. **环境准备**：
   - 安装任意 PHP 8.1+ 环境（推荐下载 [PHP for Windows](https://windows.php.net/download/) 或使用 **phpStudy (小皮面板)**）；
   - 在 `php.ini` 中解除注释开启常用扩展：`curl`、`mbstring`、`openssl`、`sockets`、`fileinfo`、`pdo_mysql`、`pdo_sqlite`。
2. **一键启动**：
   - 双击项目根目录下的 **`start.bat`**；
   - 脚本将自动检测环境、创建 `runtime` 目录并配置本地环境；
   - 自动在默认浏览器中打开 `http://127.0.0.1:8000/`，直接进入 **5 步极光玻璃拟态安装向导**。

---

### 方案 4：宝塔面板 (aaPanel / BT-Panel) 搭建指南

1. **新建站点**：
   - 登录宝塔面板 ➔「网站」➔「添加站点」；
   - 填写域名，PHP 版本选择 **PHP-81** 或 **PHP-82**。
2. **安装扩展与解除禁用**：
   - 进入宝塔「软件商店」➔ 找到对应的 PHP 版本 ➔「安装扩展」；
   - 安装 `fileinfo` 与 `redis` 扩展；
   - 进入「禁用函数」列表，如包含 `putenv`、`pcntl_signal`，建议从禁用列表中移除。
3. **上传源码与指定运行目录**：
   - 将本项目源码上传解压至网站根目录；
   - 点击该站点「设置」➔「网站目录」：
     - **网站目录**：保持为 `/www/wwwroot/你的网站目录/`
     - **运行目录 (Run directory)**：务必选择并切换为 **`/public`**（非常关键）
     - 点击「保存」。
4. **设置伪静态规则 (URL Rewrite)**：
   - 在站点设置中选择「伪静态」，粘贴以下规则并保存：
     ```nginx
     location / {
         try_files $uri $uri/ /index.html;
     }

     location ^~ /api/ {
         try_files $uri $uri/ /index.php?$query_string;
     }

     location ~ /\.(env|git|lock) {
         deny all;
     }
     ```
5. **添加定时计划任务**：
   - 进入宝塔左侧「计划任务」➔「添加任务」；
   - 任务类型：**Shell 脚本**；
   - 执行周期：**N分钟 ➔ 每 1 分钟执行一次**；
   - 脚本内容：
     ```bash
     cd /www/wwwroot/你的网站目录 && php app/Console/cron.php >> /dev/null 2>&1
     ```
   - 保存后即可实现 24 小时全自动资产多源发现、接管风险监控与多渠道告警！

---

## 三、首次访问安装向导说明

首次打开平台首页，系统将自动重定向至 `/install`：

1. **第 1 步：环境依赖自检**
   - 逐项检测 PHP 运行时、pdo_mysql、openssl、curl、fileinfo、sockets、目录可写权限；
   - 全部合规呈现绿色 Soft Tag，支持一键下一步。
2. **第 2 步：数据库配置与白名单迁移**
   - 输入 MySQL 主机、端口、用户名与密码；支持勾选「若不存在则自动创建」；
   - 点击下一步，系统安全执行内置白名单 DDL 迁移，构建 19 张核心资产与日志表。
3. **第 3 步：管理员账号创建**
   - 设置特权管理员用户名、通知邮箱与密码（强制密码强度校验：≥8 位且必须含大小写字母+数字）。
4. **第 4 步：初始告警渠道设置**
   - 支持填写企业微信群机器人 Webhook 地址；支持跳过并在后台随时扩展（邮件、钉钉、飞书等）。
5. **第 5 步：固化安全锁**
   - 系统生成物理文件锁 `runtime/install.lock`，数据库标记 `installed=1`，销毁临时 Token，永久锁死安装入口（后续任何访问安装接口严格返回 `403 Forbidden`）。

---

## 四、常见问题排查与运维安全建议

1. **接口返回 428 Precondition Required 是什么原因？**
   - 这是系统的安装守卫机制（`EnsureSystemInstalled`），表示系统尚未完成安装引导；直接打开站点首页将自动进入向导，安装完成后该提示自动消失。
2. **误删 install.lock 如何重新初始化？**
   - 锁文件位于 `runtime/install.lock`；若需彻底重装，请备份数据库后删除该文件并清空数据库，刷新页面即可重新调起向导。
3. **DNS 检测如何规避被封与限流？**
   - 进入后台「网络代理池」批量导入节点；
   - 在「主域名管理」抽屉中将网络出口配置为该代理组；系统将通过 DoH over 代理发起并发解析，完全隐藏源站 IP。
4. **生产环境安全加固忠告**：
   - 确保外网无法直接下载 `.env` 文件（Nginx 默认配置已拦截）；
   - 强制启用 HTTPS 加密（Let's Encrypt 或已有证书）；
   - 仅限在官方授权的 SRC 项目与自有资产范围内进行探测。

---

## 五、合规与授权声明

本软件定位为已获授权资产的攻防演练防御工具与资产变动监测平台。使用者必须严格遵守《中华人民共和国网络安全法》及相关法律法规。禁止使用本工具针对未经书面授权的目标实施扫描、渗透或任何未授权测试行为。作者与贡献者不对使用者的任何违规行为承担连带法律责任。
