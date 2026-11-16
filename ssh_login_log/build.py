# -*- coding: utf-8 -*-
"""打包宝塔插件：src/ -> dist/<name>/ 组装校验，成品输出到本目录 <name>-<ver>.zip"""
import os
import re
import sys
import json
import shutil
import zipfile
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "src")
DIST = os.path.join(HERE, "dist")
NAME = "ssh_login_log"
FILES = ["info.json", "index.html", "install.sh", "ssh_login_log_main.py", "icon.png"]


def main():
    for f in FILES:
        p = os.path.join(SRC, f)
        if not os.path.isfile(p):
            print("缺少文件: %s" % p)
            return 1

    info = json.load(open(os.path.join(SRC, "info.json"), encoding="utf-8"))
    info["versions"] = (sys.argv[1] if len(sys.argv) > 1 else info.get("versions", "1.0"))
    info["date"] = datetime.date.today().isoformat()

    out_dir = os.path.join(DIST, NAME)
    if os.path.isdir(out_dir):
        shutil.rmtree(out_dir)
    os.makedirs(out_dir)

    for f in FILES:
        shutil.copy2(os.path.join(SRC, f), os.path.join(out_dir, f))
    with open(os.path.join(out_dir, "info.json"), "w", encoding="utf-8") as fp:
        json.dump(info, fp, ensure_ascii=False, indent=4)

    # 语法检查
    src = open(os.path.join(out_dir, "ssh_login_log_main.py"), encoding="utf-8").read()
    compile(src, "ssh_login_log_main.py", "exec")

    zip_path = os.path.join(HERE, "%s-%s.zip" % (NAME, info["versions"]))
    for old in os.listdir(HERE):
        if re.match(r"^%s-\d[\d.]*\.zip$" % NAME, old):
            try:
                os.remove(os.path.join(HERE, old))
            except Exception:
                pass
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as z:
        for f in FILES:
            z.write(os.path.join(out_dir, f), "%s/%s" % (NAME, f))

    size = os.path.getsize(zip_path)
    print("版本 %s" % info["versions"])
    print("目录 %s" % out_dir)
    print("压缩包 %s (%.1f KB)" % (zip_path, size / 1024.0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
