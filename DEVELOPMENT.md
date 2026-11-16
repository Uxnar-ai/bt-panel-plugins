# 宝塔面板插件开发规则

基于 **宝塔面板 9.x / 13.x** 实测整理（主要验证版本 13.2.0，Python 3.13 + pyenv）。适用于本地自建插件，未经官方商店审核。

---

## 一、最小可用结构

```
/www/server/panel/plugin/<plugin_name>/
├─ info.json               插件信息（面板据此显示与判定已安装）
├─ <plugin_name>_main.py   后端主程序（类名 = 文件名去掉 .py）
├─ index.html              前端页面（自包含，面板以独立页面加载）
├─ install.sh              安装 / 卸载脚本
└─ icon.png                图标，256×256 透明 PNG
```

**硬性约束**

| 项 | 规则 |
| --- | --- |
| 目录名 | 即插件名 `plugin_name`，全小写下划线，同时是接口里的 `name` 参数 |
| Python 文件名 | `<plugin_name>_main.py`，必须完全一致 |
| 类名 | 与文件名一致：`class <plugin_name>_main:` |
| 入口 HTML | 必须叫 `index.html` |

类名或文件名对不上，面板报「插件不存在」或方法调不到，且不给具体错误，排查成本极高。

---

## 二、info.json

```json
{
  "title": "SSH登录审计",
  "name": "ssh_login_log",
  "ps": "一句话描述，显示在插件列表",
  "versions": "2.5",
  "checks": "/www/server/panel/plugin/ssh_login_log",
  "author": "your-name",
  "home": "https://www.bt.cn/bbs",
  "date": "2026-11-16",
  "display": 1,
  "sort": 100,
  "beta": false,
  "type": 0,
  "id": 0
}
```

| 字段 | 说明 |
| --- | --- |
| `name` | 必须与目录名一致，否则前台请求找不到插件 |
| `versions` | 纯数字点号，用于显示与升级判断；改前端后建议递增，便于识别 |
| `checks` | 安装检测路径，一般就是插件目录本身 |
| `display` | `1` 表示在插件列表显示 |
| `ps` | 会显示在列表，写清楚用途 |

---

## 三、后端约定

### 3.1 方法即接口

类里的公开方法自动成为接口，方法名就是 `s` 参数值：

```python
# -*- coding: utf-8 -*-
import os, sys, json

if "/www/server/panel/class" not in sys.path:
    sys.path.insert(0, "/www/server/panel/class")

import public


class my_plugin_main:
    def __init__(self):
        pass

    def get_list(self, args=None):
        return public.returnMsg(True, "ok")   # 或自定义 dict
```

- 参数对象是 `public.dict_obj`，用 `args.xxx` 取值；取不到时用 `getattr(args, "xxx", 默认值)`
- 返回值必须是可 JSON 序列化的 dict

### 3.2 返回格式

```python
# 成功
{"status": True, "data": {...}}

# 失败
{"status": False, "msg": "错误说明"}
```

`status` 为 `False` 时，前端把 `msg` 当作 toast 文案。**`msg` 里不要塞英文 i18n key**，面板语言包会尝试翻译，容易变成看不懂的提示。

### 3.3 能用的公共库

| 用途 | 调用 |
| --- | --- |
| 返回消息 | `public.returnMsg(True/False, msg)` |
| 读文件 | `public.readFile(path)` |
| 写文件 | `public.writeFile(path, content)` |
| 执行命令 | `public.ExecShell(cmd)` |
| 参数对象 | `public.dict_obj()` |
| 面板版本 | `public.version()` 或读 `class/common.py` 的 `g.version` |
| 防火墙 | `from firewall_new import firewalls` → `AddDropAddress(port, addr, types)` |

插件私有数据建议放 `<插件目录>/data/`，面板升级不影响。

---

## 四、前端约定（最容易踩坑）

### 4.1 接口调用

```js
fetch('/plugin?action=a&name=' + NAME + '&s=' + method, {
  method: 'POST',
  credentials: 'same-origin',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8' },
  body: new URLSearchParams(params).toString()
})
```

等价于面板自带的 `$.post('/plugin?action=a&name=xxx&s=yyy', {...})`。

### 4.2 CSRF（面板 13.x 必踩）

`/plugin` 路由在 `panel/publicObject()` 里做 CSRF 校验，规则是 `check_csrf()`：

```python
http_token = request.headers.get('x-http-token')
if not http_token: return False
if http_token != session['request_token_head']: return False
```

缺失或不匹配时返回 `INIT_CSRF_ERR`，界面显示**「权限认证失败，请尝试刷新页面，若多次出现请重新登录面板」**。表现是页面能打开但所有数据都空、每次都弹这个提示。

取值顺序（从稳到不稳）：

```js
1. window.vite_public_request_token            // 面板布局里的全局变量，最可靠
2. window.parent.vite_public_request_token    // 插件在 iframe 内
3. 父文档 #request_token_head 节点的 token 属性
4. document.cookie 里的 request_token_head    // 部分版本才有
```

拿到后放进请求头 `x-http-token: <token>`。取不到就盲发——旧版本面板不校验，加了也无害。

**注意**：`$.ajaxSetup` 的全局头只对走 jQuery 的请求有效，自己用 `fetch` 必须手动加。

### 4.3 页面在弹窗里，宽度很窄

插件页被装进面板弹窗的 iframe，实测常见尺寸只有 **570 × 450**，且部分版本会把 iframe 按大宽度排版后整体缩放，导致：

- 媒体查询按 1100+ 判断，窄屏规则永远不触发
- 文字被缩到 7-8px

对策：

```js
// 按真实可见宽度打标记，不依赖媒体查询
var w = document.documentElement.clientWidth;
var key = w >= 1120 ? 'xl' : w >= 980 ? 'lg' : w >= 860 ? 'md' : w >= 720 ? 'sm' : 'xs';
root.setAttribute('data-w', key);
```

CSS 用 `[data-w="xs"]` 隐藏次要列，别用固定 `min-width` 硬撑。

若 iframe 被缩放（`frameElement` 视觉宽度 < 布局宽度），可尝试消除：

```js
var f = window.frameElement;
if (f && f.getBoundingClientRect().width / f.offsetWidth < 0.96) {
  f.style.zoom = '1';
  f.style.transform = 'none';
  f.style.width = '100%';
}
```

跨域 / sandbox 装载时 `frameElement` 抛异常，整段降级，所以必须有兜底排版。

### 4.4 高度与 body 重置

- **不要用 `100vh` 锁高度**：iframe 里不可靠，内容一多就把页面顶长，出现内外双滚动条
- 用 `min-height` 让内容撑开，或 `document.documentElement.clientHeight` 手动量
- 自带重置，别依赖面板：`html,body{margin:0;padding:0}`。缺这行时面板默认 8px 边距会把内容顶出容器，底部按钮被切掉

### 4.5 主题

面板自身有明暗主题，插件页要么跟随面板，要么提供开关。判断顺序：

1. 父窗口 `body` / `documentElement` 的 class 是否含 `dark` / `bt-dark` / `theme-dark`
2. 父窗口 body 的 `background-color` 亮度（`l < 120` 视为深色）
3. 都读不到才回退 `prefers-color-scheme`

**不要**把 `prefers-color-scheme` 放在面板判断之前：面板浅色 + 系统深色时会出现浅色面板里蹦出一个深色插件页。

### 4.6 静态缓存

插件页由 `send_file` 返回，带 `Cache-Control: max-age=86400`。改完前端**必须硬刷新**（`Ctrl + F5`），否则看到的还是旧页面，极易误判成「没生效」。

---

## 五、install.sh

```bash
#!/bin/bash
# $1: install | uninstall

PLUGIN_DIR=/www/server/panel/plugin/my_plugin

if [ "$1" = "uninstall" ]; then
    rm -rf "${PLUGIN_DIR}/data"
    exit 0
fi

mkdir -p "${PLUGIN_DIR}/data"
chmod 755 "${PLUGIN_DIR}"/*.py 2>/dev/null
chmod 755 "${PLUGIN_DIR}/install.sh" 2>/dev/null
exit 0
```

要求：

- 必须能被执行：`chmod +x install.sh`
- 卸载分支只清插件自己的数据目录，**不要删系统文件**
- 不要在里面装 pip 包，面板升级会重置环境；需第三方库时用面板自带 `pyenv`

---

## 六、调试

### 6.1 绕过 HTTP 直接调方法（最快）

```bash
/www/server/panel/pyenv/bin/python - <<'PY'
import sys
sys.path.insert(0, '/www/server/panel/class')
sys.path.insert(0, '/www/server/panel/plugin/my_plugin')
from my_plugin_main import my_plugin_main
p = my_plugin_main()
print(p.get_list({}))
PY
```

### 6.2 走面板真实加载链（验证命名/类名是否正确）

```python
import sys
sys.path.insert(0, '/www/server/panel/class')
import public
from pluginAuth import Plugin

pl = Plugin('my_plugin')
args = public.dict_obj()
args.s = 'get_list'
print(pl.exec_fun(args))
```

这条能过，说明文件名、类名、方法名全部符合规范。前面那种直连方式过了但这条不过，就是命名问题。

### 6.3 看面板日志

| 用途 | 路径 |
| --- | --- |
| 面板错误 | `/www/server/panel/logs/error.log` |
| 请求记录（含 URI、参数、耗时） | `/www/server/panel/logs/request/YYYY-MM-DD.json` |
| Python 版本 | `/www/server/panel/pyenv/bin/python -V` |

请求日志里 `grep <plugin_name>` 能确认前端到底有没有发出请求，以及返回码。

---

## 七、打包

zip 结构必须是「顶层一个目录 = 插件名」：

```
my_plugin.zip
└─ my_plugin/
   ├─ info.json
   ├─ my_plugin_main.py
   ├─ index.html
   ├─ install.sh
   └─ icon.png
```

直接 `zip` 插件目录（父级包含插件目录），不要压缩目录内的文件散装。

打包脚本示例：

```python
import os, zipfile
SRC = "src"; NAME = "my_plugin"
with zipfile.ZipFile("dist/%s.zip" % NAME, "w", zipfile.ZIP_DEFLATED) as z:
    for f in ("info.json", "%s_main.py" % NAME, "index.html", "install.sh", "icon.png"):
        z.write(os.path.join(SRC, f), "%s/%s" % (NAME, f))
```

---

## 八、常见问题速查

| 现象 | 原因 | 处理 |
| --- | --- | --- |
| 权限认证失败 / 所有接口空 | 13.x CSRF，缺 `x-http-token` | 前端补请求头，见 4.2 |
| 改了前端没变化 | 24h 静态缓存 | `Ctrl + F5`，或升 `versions` |
| 插件列表里看不到 | `info.json` 的 `name` 与目录名不符 / `display` 为 0 | 对齐后重启面板 |
| 接口 404 / 方法调不到 | 文件名、类名、方法名不匹配 | 用 6.2 的方式验证 |
| 弹窗里内容被压扁、字很小 | iframe 被缩放 + 媒体查询按大宽度判断 | 见 4.3 |
| 底部按钮看不到 | 缺 `html,body{margin:0}` 或用了 `100vh` | 见 4.4 |
| 浅色面板里插件页是深色 | 主题判断顺序反了 | 面板优先，系统兜底 |
| 封禁不生效 | 面板防火墙接口签名变化 | 回退 `ufw` / `iptables` 双通道 |

---

## 九、发布前检查

- [ ] `info.json` 的 `name` = 目录名 = zip 内目录名
- [ ] 后端类名 = 文件名 = `<plugin_name>_main`
- [ ] 所有接口能返回 `status: true`，异常路径返回 `status: false` + 中文 `msg`
- [ ] 前端请求带 `x-http-token`
- [ ] 570px 宽度下布局不挤压、不截断、底部按钮可见
- [ ] 明暗两套主题都看过
- [ ] `install.sh` 可执行，卸载分支只删 `data`
- [ ] zip 内不带 `__pycache__`、`data/`、测试脚本、日志
