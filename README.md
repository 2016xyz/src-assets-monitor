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

系统支持 **Linux 原生**、**Windows 本地**、**Docker 容器**、**宝塔面板** 四种部署形态。

---

### 方案 1：Linux 生产环境原生搭建 (Ubuntu / Debian / CentOS)

#### 1.1 一键自动化安装 (推荐)
```bash
# 克隆仓库
git clone https://github.com/2016xyz/src-assets-monitor.git
cd src-assets-monitor

# 授予执行权限并运行一键安装脚本
chmod +x install.sh
sudo ./install.sh
```

#### 1.2 手动安装步骤 (Step-by-Step)
1. **安装 PHP 8.1+ 及扩展**：
   ```bash
   # Ubuntu / Debian:
   sudo apt update
   sudo apt install -y php-cli php-fpm php-mysql php-sqlite3 php-curl php-mbstring php-xml php-openssl php-sockets

   # CentOS / RHEL 8+:
   sudo dnf install -y epel-release
   sudo dnf install -y php-cli php-fpm php-mysqlnd php-curl php-mbstring php-xml php-sockets
   ```
2. **初始化配置与目录权限**：
   ```bash
   cp .env.example .env
   mkdir -p runtime public/uploads
   sudo chown -R www-data:www-data runtime public/uploads
   sudo chmod -R 775 runtime public/uploads
   ```
3. **配置 Nginx 虚拟主机**：
   编辑 `/etc/nginx/sites-available/src-monitor.conf`（CentOS 为 `/etc/nginx/conf.d/src-monitor.conf`）：
   ```nginx
   server {
       listen 80;
       server_name monitor.yourdomain.com; # 替换为您的域名或IP
       root /path/to/src-assets-monitor/public;
       index index.html index.php;

       client_max_body_size 20M;

       # 静态资源缓存
       location /assets/ {
           expires 7d;
           add_header Cache-Control "public, no-transform";
       }

       # 单页应用与静态资源
       location / {
           try_files $uri $uri/ /index.html;
       }

       # 后端 API 路由转发
       location ^~ /api/ {
           try_files $uri $uri/ /index.php?$query_string;
       }

       # PHP-FPM 解析 (根据实际 sock 文件或 127.0.0.1:9000 调整)
       location ~ \.php$ {
           fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
           fastcgi_index index.php;
           fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;
           include fastcgi_params;
           fastcgi_read_timeout 180;
       }

       # 拦截敏感文件读取
       location ~ /\.(env|git|lock) {
           deny all;
       }
   }
   ```
   启用站点并重载 Nginx：`sudo ln -s /etc/nginx/sites-available/src-monitor.conf /etc/nginx/sites-enabled/ && sudo systemctl reload nginx`。
4. **配置自动化计划任务 (Crontab)**：
   执行 `crontab -e`，添加如下行：
   ```bash
   # 每分钟自动触发资产巡检与代理健康巡检
   * * * * * cd /path/to/src-assets-monitor && php app/Console/cron.php >> /dev/null 2>&1
   ```

---

### 方案 2：Windows 本地快速运行 (开箱即用)

适用于开发调试、内网或 Windows Server 运维人员。

#### 2.1 依赖环境要求
- 安装任意 PHP 8.1+ 环境（推荐下载 [PHP for Windows](https://windows.php.net/download/) 线程安全版本，或使用 **phpStudy (小皮面板)** / **WampServer**）。
- 确保 `php.ini` 开启了以下扩展（去掉前面的分号 `;`）：
  ```ini
  extension=curl
  extension=mbstring
  extension=openssl
  extension=sockets
  extension=fileinfo
  extension=pdo_mysql
  extension=pdo_sqlite
  ```

#### 2.2 一键启动
双击项目根目录下的 **`start.bat`**：
1. 脚本将自动检测环境、创建 `runtime` 目录并配置本地环境；
2. 自动唤起默认浏览器访问 `http://127.0.0.1:8000/`；
3. 直接呈现 **5 步极光玻璃拟态安装向导**，引导完成数据库初始化配置！

---

### 方案 3：Docker & Docker Compose 一键启动 (全平台通用)

无需在宿主机配置 PHP、MySQL、Redis，全容器隔离运行。

1. **一键启动所有容器**：
   ```bash
   docker-compose up -d
   ```
2. **查看运行状态**：
   ```bash
   docker-compose ps
   ```
   默认暴露宿主机端口：
   - Web 访问入口：`http://<宿主机IP>:8080/`
   - MySQL 数据库端口：`3306`（默认 root 密码 `rootpassword`）
   - Redis 缓存端口：`6379`
3. **完成首次配置**：
   在浏览器中打开 `http://<宿主机IP>:8080/`，按步骤完成向导；在数据库步骤中，主机地址填写 **`mysql`**，端口填写 **`3306`**，密码输入 **`rootpassword`** 即可瞬间连接成功！

---

### 方案 4：宝塔面板 (aaPanel / BT-Panel) 搭建指南

国内运维环境广泛采用宝塔面板，按照以下 5 个直观步骤即可一键上线：

1. **添加站点**：
   - 登录宝塔面板 ➔「网站」➔「添加站点」；
   - 域名输入您的访问域名或服务器 IP；
   - PHP 版本务必选择 **PHP-81** 或 **PHP-82**。
2. **安装并开启必要扩展**：
   - 进入宝塔「软件商店」➔ 找到对应的 PHP 版本 ➔ 点击「设置」➔「安装扩展」；
   - 确认勾选并安装：`fileinfo`、`redis`；
   - 在「禁用函数」列表中，如存在 `putenv`、`pcntl_signal` 等，建议从禁用列表中移除以支持完整 CLI 调度。
3. **上传代码与设置运行目录**：
   - 将本项目解压至网站根目录；
   - 进入该网站「设置」➔「网站目录」：
     - **网站目录** 保持根路径：`/www/wwwroot/your-site/`
     - **运行目录 (Run directory)** 必须选择：**`/public`**（非常重要，否则无法访问入口）
     - 点击「保存」。
4. **配置伪静态 (URL Rewrite)**：
   - 在网站设置中点击「伪静态」，粘贴以下通用 Nginx 规则并保存：
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
   - 点击宝塔面板左侧「计划任务」➔「添加任务」；
   - 任务类型选择：**Shell 脚本**；
   - 执行周期：**N分钟 ➔ 每 1 分钟执行一次**；
   - 脚本内容填写：
     ```bash
     cd /www/wwwroot/your-site && php app/Console/cron.php >> /dev/null 2>&1
     ```
   - 保存即可实现 24 小时全自动资产巡检与告警推送！

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
