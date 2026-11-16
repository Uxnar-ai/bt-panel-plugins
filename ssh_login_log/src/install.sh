#!/bin/bash
# 宝塔面板插件安装脚本：ssh_login_log
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

PLUGIN_DIR="/www/server/panel/plugin/ssh_login_log"

if [ "$1" == "uninstall" ]; then
    rm -rf "$PLUGIN_DIR/data"
    exit 0
fi

mkdir -p "$PLUGIN_DIR/data"
chmod 700 "$PLUGIN_DIR/data"
chmod 644 "$PLUGIN_DIR/index.html" 2>/dev/null
chmod 644 "$PLUGIN_DIR/info.json" 2>/dev/null
chmod 755 "$PLUGIN_DIR/ssh_login_log_main.py" 2>/dev/null

if [ -f "$PLUGIN_DIR/data/config.json" ]; then
    chmod 600 "$PLUGIN_DIR/data/config.json"
fi

echo "install ok"
exit 0
