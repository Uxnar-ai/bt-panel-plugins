# 宝塔面板插件集合

自用的宝塔面板（BT-Panel）插件收纳库。一个目录一个插件，源码和打包成品放在一起，可直接导入面板使用。

## 插件列表

| 插件 | 说明 | 版本 |
| --- | --- | --- |
| [ssh_login_log](ssh_login_log/) | SSH 登录审计：登录记录、失败爆破统计、在线会话、一键封禁 IP / 网段、白名单 | 2.5 |

## 目录规范

每个插件目录结构一致：

```
<plugin_name>/
├─ src/                       源码
│  ├─ info.json               插件信息（title / name / versions / ps）
│  ├─ <plugin_name>_main.py   主程序，类名与文件名一致
│  ├─ index.html              前端页面
│  ├─ install.sh              安装脚本
│  └─ icon.png                图标
├─ <plugin_name>-<ver>.zip    已打包成品
└─ README.md                  插件说明
```

## 安装

1. 面板 → 软件商店 → 导入插件，选中插件目录下的 zip
2. 安装完成后在「已安装」里点设置
3. 如果界面还是旧样子，`Ctrl + F5` 强制刷新（面板对插件页有 24 小时静态缓存）

## 开发约定

- Python 3，只用标准库；面板自带 `pyenv` 解释器
- 后端方法名即接口名，前端通过 `/plugin?action=a&name=<plugin>&s=<method>` 调用
- 面板 13.x 对 `/plugin` 强制校验 `x-http-token` 请求头，缺失会返回 `INIT_CSRF_ERR`（界面显示「权限认证失败」）。前端需从父窗口 `window.vite_public_request_token` 或 cookie 取值并带上
- 页面自适应面板弹窗宽度，窄容器下按列优先级折叠次要列
