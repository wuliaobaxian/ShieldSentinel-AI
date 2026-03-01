@echo off
title ShieldSentinel AI 控制台
:: 1. 强制切换到脚本所在目录，处理驱动器跳转和空格
cd /d "%~dp0"
echo [1/2] 正在启动浏览器演示页面...
:: 2. 使用 start 异步打开，不阵塞后续服务器启动
start http://localhost:3001/chat
start http://localhost:3001/admin
echo [2/2] 正在启动 Next.js 服务器 (端口: 3001)...
echo --------------------------------------------------
:: 3. 启动服务器
npm run dev
:: 4. 如果服务器崩溃，保留窗口查看报错
echo --------------------------------------------------
echo [ERROR] 服务器已停止，请检查上方日志。
pause
