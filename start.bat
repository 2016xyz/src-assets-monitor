@echo off
chcp 65001 >nul
title SRC 资产检测站 - Windows 一键启动中心

echo ========================================================
echo          SRC 资产检测站 (SRC Assets Monitor)
echo              Windows 本地环境一键启动工具
echo ========================================================
echo.

:: 1. 检查 php.exe 是否可用
where php >nul 2>nul
if %errorlevel% neq 0 (
    echo [错误] 系统 PATH 环境变量中未找到 php.exe！
    echo 请先安装 PHP (建议 8.1 或更高版本)，或将其安装路径添加至系统 PATH 环境变量。
    echo 如您使用的是 phpStudy / 小皮面板，请进入设置启用 PHP 并添加到环境。
    echo.
    pause
    exit /b 1
)

:: 2. 检查并创建运行时目录
if not exist "runtime" mkdir runtime
if not exist "public\uploads" mkdir public\uploads

:: 3. 检查 .env 配置文件
if not exist ".env" (
    echo [*] 正在基于模板生成本地环境配置文件 .env ...
    copy ".env.example" ".env" >nul
)

echo [*] PHP 运行环境检测通过！
echo [*] 正在启动本地服务端口: http://127.0.0.1:8000 ...
echo [*] 首次运行将自动跳转至系统 5 步安装向导。
echo [*] 按 Ctrl + C 可随时中止服务运行。
echo.

:: 4. 自动唤起默认浏览器并拉起服务
start http://127.0.0.1:8000/
php -S 127.0.0.1:8000 -t public

pause
