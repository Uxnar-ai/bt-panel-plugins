# -*- coding: utf-8 -*-
"""对 mock 页面截图，检查浅色/深色与三个页签。用法：python dev/shot.py"""
import os
import sys
from playwright.sync_api import sync_playwright

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "shots")
URL = "http://127.0.0.1:8891/"


def main():
    if not os.path.isdir(OUT):
        os.makedirs(OUT)
    errs = []
    with sync_playwright() as p:
        try:
            b = p.chromium.launch(channel="msedge")
        except Exception:
            b = p.chromium.launch()
        ctx = b.new_context(viewport={"width": 1440, "height": 900}, device_scale_factor=1)
        pg = ctx.new_page()
        pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
        pg.on("pageerror", lambda e: errs.append("pageerror: %s" % e))

        for theme in ("light", "dark"):
            url = URL + ("" if theme == "light" else "?theme=dark")
            pg.goto(url, wait_until="networkidle")
            pg.wait_for_timeout(700)
            pg.screenshot(path=os.path.join(OUT, "events-%s.png" % theme))

            # 详情展开
            row = pg.query_selector("#tbEvents tr.row")
            if row:
                row.click()
                pg.wait_for_timeout(250)
                pg.screenshot(path=os.path.join(OUT, "detail-%s.png" % theme))
                row.click()
                pg.wait_for_timeout(150)

            pg.click('[data-tab="online"]')
            pg.wait_for_timeout(500)
            pg.screenshot(path=os.path.join(OUT, "online-%s.png" % theme))

            pg.click('[data-tab="rank"]')
            pg.wait_for_timeout(500)
            pg.screenshot(path=os.path.join(OUT, "rank-%s.png" % theme))

            # 禁用第一个 IP，验证按钮状态与网段区块
            btn = pg.query_selector("#rankIp [data-ban]")
            if btn:
                btn.click()
                pg.wait_for_timeout(900)
                pg.screenshot(path=os.path.join(OUT, "banned-%s.png" % theme))

            pg.click('[data-tab="white"]')
            pg.wait_for_timeout(400)
            if pg.query_selector("#wlAddr"):
                pg.fill("#wlAddr", "1.2.3.0/24")
                pg.click("#wlAdd")
                pg.wait_for_timeout(700)
            pg.screenshot(path=os.path.join(OUT, "white-%s.png" % theme))

            pg.click('[data-tab="events"]')
            pg.wait_for_timeout(300)
            # 设置面板
            pg.click("#slgGear")
            pg.wait_for_timeout(200)
            pg.screenshot(path=os.path.join(OUT, "config-%s.png" % theme))
            pg.click("#slgGear")

            # 状态过滤
            pg.select_option("#fltStatus", "failed")
            pg.wait_for_timeout(600)
            pg.screenshot(path=os.path.join(OUT, "filter-%s.png" % theme))
            pg.select_option("#fltStatus", "all")
            pg.wait_for_timeout(400)

        b.close()
    print("console errors:", errs if errs else "none")
    print("shots ->", OUT)


if __name__ == "__main__":
    main()
