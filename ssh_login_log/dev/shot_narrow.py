# -*- coding: utf-8 -*-
"""窄容器下截图，模拟宝塔面板内嵌宽度"""
import os
import sys

from playwright.sync_api import sync_playwright

BASE = "http://127.0.0.1:8891/"
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shots")
WIDTHS = [int(x) for x in (sys.argv[1:] or ["720", "900", "1100", "1440"])]


def run():
    os.makedirs(OUT, exist_ok=True)
    with sync_playwright() as p:
        b = p.chromium.launch(channel="msedge", headless=True)
        for w in WIDTHS:
            ctx = b.new_context(viewport={"width": w, "height": 820}, device_scale_factor=1)
            pg = ctx.new_page()
            errs = []
            pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
            pg.goto(BASE, wait_until="networkidle")
            pg.wait_for_timeout(900)
            path = os.path.join(OUT, "w%d.png" % w)
            pg.screenshot(path=path)
            doc_w = pg.evaluate("document.documentElement.scrollWidth")
            tbl_w = pg.evaluate("(function(){var t=document.querySelector('.slg-table');return t?t.scrollWidth:0})()")
            box = pg.evaluate("(function(){var e=document.getElementById('slg');var r=e.getBoundingClientRect();return [Math.round(r.width),Math.round(r.height)]})()")
            print("w=%d  docScrollW=%d  tableW=%d  box=%s  err=%s" % (w, doc_w, tbl_w, box, errs[:2]))
            ctx.close()
        b.close()


if __name__ == "__main__":
    run()
