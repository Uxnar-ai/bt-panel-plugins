#!/usr/bin/python
# coding: utf-8
# +-------------------------------------------------------------------
# | 宝塔面板插件：SSH 登录审计 (ssh_login_log)
# | 功能：解析 sshd 认证日志 / wtmp / btmp，输出登录事件的 IP、时间、端口、
# |       状态、用户、认证方式、会话时长，并提供统计、在线会话、CSV 导出。
# +-------------------------------------------------------------------
import os
import re
import sys
import json
import time
import gzip
import glob
import struct
import datetime
import subprocess

if "/www/server/panel/class" not in sys.path:
    sys.path.insert(0, "/www/server/panel/class")

try:
    import public
except Exception:  # 本地开发环境无面板
    public = None

PLUGIN_NAME = "ssh_login_log"
PLUGIN_PATH = os.path.dirname(os.path.abspath(__file__))
DATA_PATH = os.path.join(PLUGIN_PATH, "data")
CONF_FILE = os.path.join(DATA_PATH, "config.json")
GEO_FILE = os.path.join(DATA_PATH, "ip_area.json")
BLACK_FILE = os.path.join(DATA_PATH, "blacklist.json")
WHITE_FILE = os.path.join(DATA_PATH, "whitelist.json")
CACHE_DIR = "/dev/shm" if os.path.isdir("/dev/shm") else DATA_PATH
CACHE_FILE = os.path.join(CACHE_DIR, ".%s.cache" % PLUGIN_NAME)

DEFAULT_CONF = {
    "scan_mb": 8,        # 每个日志文件最多回读的尾部大小(MB)
    "max_events": 20000,  # 解析后最多保留的事件条数
    "refresh": 0,        # 前端自动刷新间隔(秒)，0=关闭
    "cidr_threshold": 5,  # 同一 /24 内出现多少个 IP 时提示封禁网段
    "default_tab": "events",  # 默认打开的页签
    "default_days": 3,   # 默认时间范围(天)，0=全部
    "theme": "auto",     # auto / light / dark
}

RE_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
RE_CIDR = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$")

# ---------------------------------------------------------------- 正则

RE_ISO = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[+-]\d{2}:?\d{2}|Z)?)")
RE_SYSLOG = re.compile(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")
RE_REST = re.compile(r"^(\S+)\s+([\w\-\.]+?)(?:\[(\d+)\])?:\s(.*)$")

P_ACCEPT = re.compile(r"^Accepted (\S+) for (\S+) from (\S+) port (\d+)")
P_FAIL = re.compile(r"^Failed (\S+) for (invalid user )?(\S+) from (\S+) port (\d+)")
P_INVALID = re.compile(r"^Invalid user (\S+) from (\S+) port (\d+)")
P_MAXTRY = re.compile(r"maximum authentication attempts exceeded.*? for (invalid user )?(\S+) from (\S+) port (\d+)")
P_CLOSE = re.compile(r"^Connection closed by (?:authenticating user (\S+) |invalid user (\S+) |user (\S+) )?(\S+) port (\d+)")
P_DISCONN = re.compile(r"^Disconnected from (?:invalid user )?(?:user )?(\S+) (\S+) port (\d+)")
P_RCVDISC = re.compile(r"^Received disconnect from (\S+) port (\d+)")
P_PAM = re.compile(r"^pam_unix\(sshd:session\): session (opened|closed) for user (\S+)")
P_CONNFROM = re.compile(r"^Connection from (\S+) port (\d+) on (\S+) port (\d+)")

MONTHS = {m: i + 1 for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"])}

STATUS_TEXT = {
    "success": "成功",
    "failed": "密码错误",
    "invalid": "无效用户",
    "breach": "尝试超限",
    "closed": "认证中断",
}


def _now():
    return int(time.time())


def _deep_get(args, key, default=None):
    try:
        v = args.get(key)
    except Exception:
        try:
            v = getattr(args, key)
        except Exception:
            v = None
    if v is None or v == "":
        return default
    return v


def _to_int(v, default=0):
    try:
        return int(str(v).strip())
    except Exception:
        return default


class ssh_login_log_main:

    def __init__(self):
        for p in (DATA_PATH, CACHE_DIR):
            if not os.path.isdir(p):
                try:
                    os.makedirs(p, 0o600)
                except Exception:
                    pass
        self._conf = None

    # ------------------------------------------------------------ 基础

    def _read_file(self, path, mode="r"):
        try:
            with open(path, mode) as f:
                return f.read()
        except Exception:
            return ""

    def _write_file(self, path, body):
        try:
            d = os.path.dirname(path)
            if d and not os.path.isdir(d):
                os.makedirs(d, 0o600)
            with open(path, "w") as f:
                f.write(body)
            return True
        except Exception:
            return False

    def get_conf(self):
        if self._conf is None:
            conf = dict(DEFAULT_CONF)
            raw = self._read_file(CONF_FILE)
            if raw:
                try:
                    conf.update(json.loads(raw))
                except Exception:
                    pass
            self._conf = conf
        return self._conf

    def _ok(self, data):
        return {"status": True, "data": data}

    def _err(self, msg):
        return {"status": False, "msg": str(msg)}

    # ------------------------------------------------------------ 数据源

    def _log_candidates(self):
        out = []
        env = os.environ.get("SLG_LOG_DIR")
        if env and os.path.isdir(env):
            for name in ("auth.log", "secure", "messages"):
                p = os.path.join(env, name)
                if os.path.isfile(p):
                    out.append({"path": p, "kind": name.replace(".log", "")})
                for extra in (".1", ".2"):
                    q = p + extra
                    if os.path.isfile(q):
                        out.append({"path": q, "kind": name.replace(".log", "")})
            if out:
                return out

        for base, kind in (("/var/log/auth.log", "auth"),
                           ("/var/log/secure", "secure"),
                           ("/var/log/messages", "messages")):
            if os.path.isfile(base):
                out.append({"path": base, "kind": kind})
                for suf in (".1", ".2.gz", "-1"):
                    if os.path.isfile(base + suf):
                        out.append({"path": base + suf, "kind": kind})
            # CentOS 轮转：secure-20260101
            for idx, p in enumerate(sorted(glob.glob(base + "-*"), reverse=True)[:2]):
                out.append({"path": p, "kind": kind})
        return out

    def _has_journal(self):
        for p in ("/usr/bin/journalctl", "/bin/journalctl"):
            if os.path.isfile(p):
                return p
        return ""

    def _tail_text(self, path, max_bytes):
        try:
            if path.endswith(".gz"):
                with gzip.open(path, "rt", errors="replace") as f:
                    lines = f.readlines()
                return "".join(lines[-40000:])
            size = os.path.getsize(path)
            with open(path, "rb") as f:
                if size > max_bytes:
                    f.seek(size - max_bytes)
                    f.readline()
                data = f.read()
            return data.decode("utf-8", "replace")
        except Exception:
            return ""

    def _journal_text(self, max_lines):
        jc = self._has_journal()
        if not jc:
            return ""
        cmd = [jc, "-o", "short-iso", "--no-pager", "-n", str(max_lines),
               "-t", "sshd", "-t", "sshd-session"]
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=20)
            return p.stdout.decode("utf-8", "replace")
        except Exception:
            return ""

    # ------------------------------------------------------------ 日志解析

    def _parse_ts(self, line):
        """返回 (ts, 剩余内容)"""
        m = RE_ISO.match(line)
        if m:
            raw = m.group(1)
            rest = line[m.end():].strip()
            try:
                s = raw.replace("Z", "+00:00")
                if " " in s and "T" not in s:
                    s = s.replace(" ", "T", 1)
                dt = datetime.datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=datetime.timezone.utc)
                return int(dt.timestamp()), rest
            except Exception:
                pass
        m = RE_SYSLOG.match(line)
        if m:
            raw = m.group(1)
            rest = line[m.end():].strip()
            try:
                mon, day, clock = raw.split()
                hh, mm, ss = clock.split(":")
                now = datetime.datetime.now()
                year = now.year
                dt = datetime.datetime(year, MONTHS[mon], int(day), int(hh), int(mm), int(ss))
                if dt.timestamp() > time.time() + 86400:
                    dt = dt.replace(year=year - 1)
                return int(dt.timestamp()), rest
            except Exception:
                return None, rest
        return None, line

    def _scan_text(self, text, source):
        """把一段日志文本解析为事件列表"""
        events = []
        sessions = {}   # pid -> {"open": ts, "user": u, "ip": ip, "port": p}
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            ts, rest = self._parse_ts(line)
            if ts is None:
                continue
            m = RE_REST.match(rest)
            if m:
                host, prog, pid, msg = m.group(1), m.group(2), _to_int(m.group(3)), m.group(4)
            else:
                host, prog, pid, msg = "", "", 0, rest
            if prog.lower() not in ("sshd", "sshd-session", "sshd-auth", "sshd_main"):
                continue
            ev = self._classify(ts, msg, pid, source, line)
            if not ev:
                # 会话生命周期只做关联，不单独成行
                p = P_PAM.match(msg)
                if p and pid:
                    if p.group(1) == "opened":
                        sessions.setdefault(pid, {})["open"] = ts
                    else:
                        rec = sessions.get(pid)
                        if rec and rec.get("open"):
                            rec["close"] = ts
                continue
            if ev["status"] == "success" and pid:
                sessions.setdefault(pid, {}).update(
                    {"open": ts, "user": ev["user"], "ip": ev["ip"], "port": ev["port"]})
                ev["_pid"] = pid
            events.append(ev)

        # 回填会话时长
        dur_by_pid = {}
        for pid, rec in sessions.items():
            if rec.get("open") and rec.get("close"):
                dur_by_pid[pid] = max(0, rec["close"] - rec["open"])
        for ev in events:
            pid = ev.pop("_pid", 0)
            if pid and pid in dur_by_pid:
                ev["duration"] = dur_by_pid[pid]
        return events

    def _classify(self, ts, msg, pid, source, raw):
        base = {"ts": ts, "user": "", "ip": "", "port": 0, "method": "",
                "status": "", "pid": pid, "src": source, "duration": 0, "raw": raw}

        m = P_ACCEPT.match(msg)
        if m:
            base.update({"status": "success", "method": m.group(1), "user": m.group(2),
                         "ip": m.group(3), "port": _to_int(m.group(4))})
            kp = msg.split("ssh2:", 1)
            if len(kp) > 1 and "SHA256" in kp[1]:
                base["key"] = kp[1].strip().split()[0] if kp[1].strip() else ""
            return base

        m = P_FAIL.match(msg)
        if m:
            base.update({"status": "invalid" if m.group(2) else "failed",
                         "method": m.group(1), "user": m.group(3),
                         "ip": m.group(4), "port": _to_int(m.group(5))})
            return base

        m = P_INVALID.match(msg)
        if m:
            base.update({"status": "invalid", "user": m.group(1),
                         "ip": m.group(2), "port": _to_int(m.group(3))})
            return base

        m = P_MAXTRY.search(msg)
        if m:
            base.update({"status": "breach", "user": m.group(2),
                         "ip": m.group(3), "port": _to_int(m.group(4))})
            return base

        m = P_CLOSE.match(msg)
        if m:
            user = m.group(1) or m.group(2) or m.group(3) or ""
            ip, port = m.group(4), _to_int(m.group(5))
            if not user and "preauth" not in msg:
                return None
            if not user:
                return None
            base.update({"status": "closed", "user": user, "ip": ip, "port": port})
            return base

        return None

    def _parse_wtmp(self, path, kind):
        """解析 utmp 结构（wtmp/btmp），作为日志轮转后的补充来源"""
        events = []
        try:
            if not os.path.isfile(path):
                return events
            size = os.path.getsize(path)
            if size < 384 or size % 384 != 0:
                return events
            with open(path, "rb") as f:
                f.seek(max(0, size - 384 * 2000))
                data = f.read()
            for i in range(0, len(data) - 383, 384):
                r = data[i:i + 384]
                ut_type = struct.unpack("<h", r[0:2])[0]
                if ut_type not in (7, 8):
                    continue
                line = r[8:40].split(b"\0")[0].decode("utf-8", "replace")
                user = r[44:76].split(b"\0")[0].decode("utf-8", "replace")
                host = r[76:332].split(b"\0")[0].decode("utf-8", "replace")
                sec = struct.unpack("<i", r[340:344])[0]
                if sec <= 0 or not user:
                    continue
                if kind == "btmp":
                    events.append({"ts": sec, "user": user, "ip": host, "port": 0,
                                   "method": "", "status": "failed", "pid": 0,
                                   "src": "btmp", "duration": 0,
                                   "raw": "btmp: %s %s %s" % (user, host, line)})
                else:
                    events.append({"ts": sec, "user": user, "ip": host, "port": 0,
                                   "method": "", "status": "success", "pid": 0,
                                   "src": "wtmp", "duration": 0,
                                   "raw": "wtmp: %s %s %s" % (user, host, line)})
        except Exception:
            pass
        return events

    # ------------------------------------------------------------ 聚合 + 缓存

    def _signature(self, files):
        sig = []
        for f in files:
            try:
                st = os.stat(f["path"])
                sig.append("%s:%d:%d" % (f["path"], st.st_size, int(st.st_mtime)))
            except Exception:
                sig.append(f["path"] + ":0")
        for extra in ("/var/log/wtmp", "/var/log/btmp"):
            try:
                st = os.stat(extra)
                sig.append("%s:%d:%d" % (extra, st.st_size, int(st.st_mtime)))
            except Exception:
                pass
        return "|".join(sig)

    def _collect(self, force=False):
        conf = self.get_conf()
        files = self._log_candidates()
        sig = self._signature(files)
        if not force:
            cached = self._read_file(CACHE_FILE, "r")
            if cached:
                try:
                    obj = json.loads(cached)
                    if obj.get("sig") == sig and _now() - obj.get("at", 0) < 60:
                        return obj
                except Exception:
                    pass

        max_bytes = max(1, _to_int(conf.get("scan_mb"), 8)) * 1024 * 1024
        max_events = max(1000, _to_int(conf.get("max_events"), 20000))
        events = []
        used = []
        for f in files:
            text = self._tail_text(f["path"], max_bytes)
            if not text:
                continue
            used.append(f["path"])
            events.extend(self._scan_text(text, f["kind"]))

        if not events:
            text = self._journal_text(max_events)
            if text:
                used.append("journalctl")
                events.extend(self._scan_text(text, "journal"))

        # wtmp / btmp 补充（日志轮转后仍可回溯）
        for path, kind in (("/var/log/wtmp", "wtmp"), ("/var/log/btmp", "btmp")):
            try:
                if os.path.isfile(path) and os.path.getsize(path) % 384 == 0 and os.path.getsize(path) >= 384:
                    events.extend(self._parse_wtmp(path, kind))
            except Exception:
                pass

        events = self._dedupe(events)
        events.sort(key=lambda e: e["ts"], reverse=True)
        if len(events) > max_events:
            events = events[:max_events]

        obj = {"sig": sig, "at": _now(), "sources": used, "events": events}
        try:
            self._write_file(CACHE_FILE, json.dumps(obj, ensure_ascii=False))
        except Exception:
            pass
        return obj

    def _dedupe(self, events):
        """去掉 wtmp/btmp 与日志重复的记录，并按 (ts,user,ip,status,port) 去重"""
        log_events = [e for e in events if e["src"] not in ("wtmp", "btmp")]
        extra = [e for e in events if e["src"] in ("wtmp", "btmp")]
        min_ts = min([e["ts"] for e in log_events], default=0)

        uniq = []
        seen = set()
        for e in log_events:
            k = (e["ts"], e["user"], e["ip"], e["status"], e["port"])
            if k in seen:
                continue
            seen.add(k)
            uniq.append(e)

        for e in extra:
            if e["src"] == "wtmp":
                # wtmp 无端口，只要日志里同用户同 IP 在 ±120s 内有成功记录就跳过
                if e["ts"] >= min_ts - 120 and self._near(uniq, e, 120):
                    continue
            else:
                if self._near(uniq, e, 300):
                    continue
            uniq.append(e)
        return uniq

    @staticmethod
    def _near(events, ev, window):
        for e in events:
            if e["user"] == ev["user"] and e["ip"] == ev["ip"] and abs(e["ts"] - ev["ts"]) <= window:
                return True
        return False

    def _filtered(self, events, status="all", keyword="", user="", since=0):
        out = []
        kw = (keyword or "").strip().lower()
        fail_set = ("failed", "invalid", "breach")
        for e in events:
            if since and e["ts"] < since:
                continue
            st = e["status"]
            if status == "success" and st != "success":
                continue
            if status == "failed" and st not in fail_set:
                continue
            if status == "closed" and st != "closed":
                continue
            if status not in ("all", "success", "failed", "closed", "") and st != status:
                continue
            if user and e["user"] != user:
                continue
            if kw:
                hay = "%s %s %s %s" % (e["user"], e["ip"], e.get("method", ""), e.get("raw", ""))
                if kw not in hay.lower():
                    continue
            out.append(e)
        return out

    def _decorate(self, ev):
        ts = ev["ts"]
        return {
            "id": "%d-%s-%s" % (ts, ev["ip"], ev["port"]),
            "ts": ts,
            "time": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts)),
            "user": ev["user"] or "-",
            "ip": ev["ip"] or "-",
            "port": ev["port"] or 0,
            "status": ev["status"],
            "status_text": STATUS_TEXT.get(ev["status"], ev["status"]),
            "method": ev["method"] or "-",
            "duration": ev["duration"] or 0,
            "src": ev["src"],
            "raw": ev.get("raw", ""),
        }

    # ------------------------------------------------------------ 黑名单 / 白名单

    @staticmethod
    def _is_ipv4(ip):
        return bool(RE_IPV4.match(ip or ""))

    @staticmethod
    def _cidr_of(ip):
        parts = (ip or "").split(".")
        if len(parts) != 4:
            return ""
        return "%s.%s.%s.0/24" % (parts[0], parts[1], parts[2])

    def _load_json(self, path, default):
        raw = self._read_file(path)
        if not raw:
            return default
        try:
            data = json.loads(raw)
            return data if isinstance(data, type(default)) else default
        except Exception:
            return default

    def _save_json(self, path, data):
        return self._write_file(path, json.dumps(data, ensure_ascii=False, indent=2))

    def _whitelist(self):
        return self._load_json(WHITE_FILE, [])

    def _blacklist(self):
        return self._load_json(BLACK_FILE, {})

    def _whitelisted(self, addr):
        if not addr:
            return False
        for it in self._whitelist():
            a = (it.get("addr") or "").strip()
            if not a:
                continue
            if a == addr:
                return True
            if a.endswith("/24") and addr.count(".") >= 3 and self._cidr_of(addr) == a:
                return True
            if addr.endswith("/24") and a.count(".") >= 3 and self._cidr_of(a) == addr:
                return True
        return False

    def _run(self, cmd, timeout=20):
        try:
            p = subprocess.run(cmd, shell=True, stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=timeout)
            return p.returncode, p.stdout.decode("utf-8", "replace").strip()
        except Exception:
            return 1, ""

    def _has_ufw(self):
        for p in ("/usr/sbin/ufw", "/usr/bin/ufw", "/sbin/ufw"):
            if os.path.isfile(p):
                return True
        return False

    def _blocked_set(self):
        """系统当前已屏蔽的地址（含面板/ufw/iptables/fail2ban 的规则）"""
        out = set()
        if self._has_ufw():
            rc, txt = self._run("ufw status")
            for line in txt.splitlines():
                if "REJECT" in line or "DENY" in line:
                    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)", line)
                    if m:
                        out.add(m.group(1))
        rc, txt = self._run("iptables -S INPUT")
        for m in re.finditer(r"-s (\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\S* .*?-j (?:DROP|REJECT)", txt):
            out.add(m.group(1))
        for addr in self._blacklist().keys():
            out.add(addr)
        return out

    def _fw_add(self, addr, note):
        """优先走面板防火墙（可在面板-安全里看到），失败再回退到系统命令"""
        try:
            import public as _p
            import firewall_new
            fw = firewall_new.firewalls()
            args = _p.dict_obj()
            args.port = addr
            args.ps = note
            res = fw.AddDropAddress(args)
            if isinstance(res, dict) and res.get("status"):
                return True, "panel"
        except Exception:
            pass
        if self._has_ufw():
            rc, txt = self._run("ufw deny from %s to any" % addr)
            if rc == 0:
                return True, "ufw"
        rc, txt = self._run("iptables -I INPUT -s %s -j DROP" % addr)
        if rc == 0:
            return True, "iptables"
        return False, txt or "系统防火墙执行失败"

    def _fw_del(self, addr):
        removed = False
        try:
            import public as _p
            import firewall_new
            row = _p.M("firewall").where("port=?", (addr,)).find()
            if row:
                fw = firewall_new.firewalls()
                args = _p.dict_obj()
                args.port = addr
                args.id = row["id"]
                fw.DelDropAddress(args)
                removed = True
        except Exception:
            pass
        if self._has_ufw():
            rc, txt = self._run("ufw delete deny from %s to any" % addr)
            removed = removed or rc == 0
        rc, txt = self._run("iptables -D INPUT -s %s -j DROP" % addr)
        removed = removed or rc == 0
        return removed

    def ban_ip(self, args=None):
        args = args or {}
        addr = str(_deep_get(args, "addr", "")).strip()
        if not (RE_IPV4.match(addr) or RE_CIDR.match(addr)):
            return self._err("只支持 IPv4 地址或 CIDR 网段")
        if self._whitelisted(addr):
            return self._err("%s 在白名单中，已拒绝禁用" % addr)
        note = str(_deep_get(args, "note", "SSH登录审计"))
        ok, via = self._fw_add(addr, note)
        if not ok:
            return self._err("禁用失败：%s" % via)
        bl = self._blacklist()
        bl[addr] = {"ts": _now(), "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "note": note, "via": via,
                    "scope": "cidr" if "/" in addr else "ip"}
        self._save_json(BLACK_FILE, bl)
        return self._ok({"addr": addr, "via": via, "blocked": True})

    def unban_ip(self, args=None):
        args = args or {}
        addr = str(_deep_get(args, "addr", "")).strip()
        if not (RE_IPV4.match(addr) or RE_CIDR.match(addr)):
            return self._err("只支持 IPv4 地址或 CIDR 网段")
        self._fw_del(addr)
        bl = self._blacklist()
        if addr in bl:
            bl.pop(addr)
            self._save_json(BLACK_FILE, bl)
        return self._ok({"addr": addr, "blocked": False})

    def get_blacklist(self, args=None):
        bl = self._blacklist()
        blocked = self._blocked_set()
        rows = []
        for addr, info in bl.items():
            rows.append({"addr": addr, "time": info.get("time", ""),
                         "note": info.get("note", ""), "via": info.get("via", ""),
                         "scope": info.get("scope", "ip")})
        rows.sort(key=lambda x: x.get("time", ""), reverse=True)
        system_only = sorted([a for a in blocked if a not in bl])
        return self._ok({"rows": rows, "blocked": sorted(blocked),
                         "system_only": system_only,
                         "whitelist": self._whitelist()})

    def get_whitelist(self, args=None):
        return self._ok({"rows": self._whitelist()})

    def add_whitelist(self, args=None):
        args = args or {}
        addr = str(_deep_get(args, "addr", "")).strip()
        if not (RE_IPV4.match(addr) or RE_CIDR.match(addr)):
            return self._err("只支持 IPv4 地址或 CIDR 网段")
        wl = self._whitelist()
        for it in wl:
            if it.get("addr") == addr:
                return self._err("%s 已在白名单" % addr)
        note = str(_deep_get(args, "note", ""))
        wl.append({"addr": addr, "note": note, "ts": _now(),
                   "time": time.strftime("%Y-%m-%d %H:%M:%S")})
        self._save_json(WHITE_FILE, wl)
        # 已在黑名单中的，加入白名单时自动解禁
        bl = self._blacklist()
        if addr in bl:
            self._fw_del(addr)
            bl.pop(addr)
            self._save_json(BLACK_FILE, bl)
        return self._ok({"rows": wl})

    def del_whitelist(self, args=None):
        args = args or {}
        addr = str(_deep_get(args, "addr", "")).strip()
        wl = [it for it in self._whitelist() if it.get("addr") != addr]
        self._save_json(WHITE_FILE, wl)
        return self._ok({"rows": wl})

    def _cidr_groups(self, events, threshold):
        groups = {}
        for e in events:
            if e["status"] not in ("failed", "invalid", "breach"):
                continue
            ip = e["ip"] or ""
            if not RE_IPV4.match(ip):
                continue
            seg = self._cidr_of(ip)
            g = groups.setdefault(seg, {"ips": {}, "hits": 0})
            g["ips"][ip] = g["ips"].get(ip, 0) + 1
            g["hits"] += 1
        out = []
        for cidr, g in groups.items():
            if len(g["ips"]) < threshold:
                continue
            out.append({
                "cidr": cidr,
                "ip_count": len(g["ips"]),
                "hits": g["hits"],
                "ips": sorted(g["ips"].items(), key=lambda x: -x[1])[:60],
            })
        out.sort(key=lambda x: (-x["ip_count"], -x["hits"]))
        return out

    # ------------------------------------------------------------ 对外接口

    def get_logs(self, args=None):
        args = args or {}
        try:
            data = self._collect(force=str(_deep_get(args, "force", "0")) == "1")
        except Exception as e:
            return self._err("读取日志失败：%s" % e)

        days = _to_int(_deep_get(args, "days", 3), 3)
        since = 0 if days <= 0 else _now() - days * 86400
        status = str(_deep_get(args, "status", "all"))
        keyword = str(_deep_get(args, "keyword", ""))
        user = str(_deep_get(args, "user", ""))
        page = max(1, _to_int(_deep_get(args, "page", 1), 1))
        limit = min(200, max(10, _to_int(_deep_get(args, "limit", 20), 20)))

        rows = self._filtered(data["events"], status, keyword, user, since)
        total = len(rows)
        start = (page - 1) * limit
        page_rows = [self._decorate(e) for e in rows[start:start + limit]]

        return self._ok({
            "total": total,
            "page": page,
            "limit": limit,
            "rows": page_rows,
            "sources": data.get("sources", []),
            "scanned_at": data.get("at", 0),
            "ports": self._sshd_port(),
        })

    def _fill_geo(self, rows):
        cache = {}
        raw = self._read_file(GEO_FILE)
        if raw:
            try:
                cache = json.loads(raw)
            except Exception:
                cache = {}
        changed = False
        for r in rows:
            ip = r["ip"]
            if ip == "-" or ip in cache:
                r["area"] = cache.get(ip, "")
                continue
            area = self._lookup_one(ip)
            if area:
                cache[ip] = area
                changed = True
            r["area"] = area
        if changed:
            self._write_file(GEO_FILE, json.dumps(cache, ensure_ascii=False))

    def _lookup_one(self, ip):
        if not ip or ip == "-":
            return ""
        try:
            if ip.startswith(("10.", "192.168.", "127.", "172.16.", "172.17.", "172.18.",
                              "172.19.", "172.2", "172.30.", "172.31.", "::1", "fe80")):
                return "内网"
        except Exception:
            pass
        if public is None:
            return ""
        try:
            info = public.get_free_ip_info(ip)
            if isinstance(info, dict):
                return (info.get("info") or "").strip()
        except Exception:
            pass
        return ""

    def get_stats(self, args=None):
        args = args or {}
        try:
            data = self._collect()
        except Exception as e:
            return self._err("读取日志失败：%s" % e)
        events = data["events"]
        now = _now()
        midnight = int(time.mktime(time.localtime(now)[:3] + (0, 0, 0, 0, 0, -1)))

        today_succ = today_fail = 0
        fail_ips = {}
        fail_users = {}
        buckets = {}
        for i in range(24):
            buckets[i] = {"success": 0, "failed": 0}

        day_start = midnight
        for e in events:
            st = e["status"]
            is_fail = st in ("failed", "invalid", "breach")
            if e["ts"] >= day_start:
                if st == "success":
                    today_succ += 1
                elif is_fail:
                    today_fail += 1
            if is_fail:
                fail_ips[e["ip"]] = fail_ips.get(e["ip"], 0) + 1
                fail_users[e["user"]] = fail_users.get(e["user"], 0) + 1
            if now - e["ts"] <= 86400:
                hour = int(time.strftime("%H", time.localtime(e["ts"])))
                if st == "success":
                    buckets[hour]["success"] += 1
                elif is_fail:
                    buckets[hour]["failed"] += 1

        online = self._online()
        top_ips = sorted(fail_ips.items(), key=lambda x: -x[1])[:8]
        top_users = sorted(fail_users.items(), key=lambda x: -x[1])[:8]
        blocked = self._blocked_set()
        wl = [it.get("addr", "") for it in self._whitelist()]
        threshold = max(2, _to_int(self.get_conf().get("cidr_threshold"), 5))

        # 最近 24 小时按时间正向排列，便于画图
        cur_hour = int(time.strftime("%H", time.localtime(now)))
        series = []
        for i in range(23, -1, -1):
            h = (cur_hour - i) % 24
            series.append({
                "hour": "%02d" % h,
                "success": buckets[h]["success"],
                "failed": buckets[h]["failed"],
            })

        return self._ok({
            "today_success": today_succ,
            "today_failed": today_fail,
            "total": len(events),
            "unique_fail_ips": len(fail_ips),
            "online": len(online),
            "series": series,
            "top_ips": [{
                "ip": k, "count": v,
                "cidr": self._cidr_of(k),
                "blocked": k in blocked,
                "whitelisted": k in wl,
            } for k, v in top_ips if k],
            "top_users": [{"user": k, "count": v} for k, v in top_users if k],
            "cidr_groups": [dict(g, blocked=g["cidr"] in blocked, whitelisted=g["cidr"] in wl)
                            for g in self._cidr_groups(events, threshold)],
            "cidr_threshold": threshold,
            "blocked": sorted(blocked),
            "blacklist_count": len(blocked),
            "whitelist": wl,
            "sources": data.get("sources", []),
            "ports": self._sshd_port(),
        })

    def _online(self):
        """当前在线 SSH 会话"""
        rows = []
        try:
            p = subprocess.run(["who"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                               timeout=10)
            text = p.stdout.decode("utf-8", "replace")
        except Exception:
            text = ""
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            m = re.match(r"^(\S+)\s+(\S+)\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}|\S+)\s*(?:\(([^)]*)\))?", line)
            if not m:
                continue
            user, tty, when, ip = m.group(1), m.group(2), m.group(3), (m.group(4) or "")
            ts = 0
            try:
                ts = int(time.mktime(time.strptime(when, "%Y-%m-%d %H:%M")))
            except Exception:
                ts = 0
            rows.append({
                "user": user, "tty": tty, "ip": ip or "-", "ts": ts,
                "time": time.strftime("%Y-%m-%d %H:%M", time.localtime(ts)) if ts else when,
                "duration": (_now() - ts) if ts else 0,
                "pid": 0, "remote_port": 0,
            })
        # 从 sshd 子进程补 pid / 源端口
        try:
            p = subprocess.run(["ss", "-tnp", "state", "established"],
                               stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
            text = p.stdout.decode("utf-8", "replace")
        except Exception:
            text = ""
        conns = []
        for line in text.splitlines():
            if "sshd" not in line:
                continue
            m = re.search(r"(\S+):(\d+)\s+(\S+):(\d+)\s+users:\(\(\"(sshd[\w\-]*)\",pid=(\d+)", line)
            if not m:
                continue
            conns.append({"local": m.group(1), "local_port": _to_int(m.group(2)),
                          "remote": m.group(3), "remote_port": _to_int(m.group(4)),
                          "pid": _to_int(m.group(6))})
        for r in rows:
            for c in conns:
                if c["remote"] == r["ip"]:
                    r["pid"] = c["pid"]
                    r["remote_port"] = c["remote_port"]
                    break
        return rows

    def get_online(self, args=None):
        rows = self._online()
        for r in rows:
            r["duration_text"] = self._dur_text(r["duration"])
        return self._ok({"rows": rows, "total": len(rows)})

    @staticmethod
    def _dur_text(sec):
        sec = int(sec or 0)
        if sec <= 0:
            return "-"
        d, sec = divmod(sec, 86400)
        h, sec = divmod(sec, 3600)
        m, s = divmod(sec, 60)
        if d:
            return "%dd %dh" % (d, h)
        if h:
            return "%dh %dm" % (h, m)
        if m:
            return "%dm %ds" % (m, s)
        return "%ds" % s

    def get_sources(self, args=None):
        files = self._log_candidates()
        rows = []
        for f in files:
            try:
                st = os.stat(f["path"])
                rows.append({"path": f["path"], "kind": f["kind"],
                             "size": st.st_size,
                             "mtime": time.strftime("%Y-%m-%d %H:%M", time.localtime(st.st_mtime))})
            except Exception:
                continue
        return self._ok({
            "files": rows,
            "journal": bool(self._has_journal()),
            "sshd_port": self._sshd_port(),
        })

    def _sshd_port(self):
        ports = []
        try:
            for conf in ("/etc/ssh/sshd_config",):
                text = self._read_file(conf)
                for line in text.splitlines():
                    m = re.match(r"^\s*Port\s+(\d+)", line)
                    if m:
                        ports.append(_to_int(m.group(1)))
            for inc in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")):
                text = self._read_file(inc)
                for line in text.splitlines():
                    m = re.match(r"^\s*Port\s+(\d+)", line)
                    if m:
                        ports.append(_to_int(m.group(1)))
        except Exception:
            pass
        return ports or [22]

    def get_config(self, args=None):
        conf = dict(self.get_conf())
        conf["sshd_port"] = self._sshd_port()
        return self._ok(conf)

    def save_config(self, args=None):
        args = args or {}
        conf = self.get_conf()
        conf["scan_mb"] = min(200, max(1, _to_int(_deep_get(args, "scan_mb", conf["scan_mb"]), 8)))
        conf["max_events"] = min(200000, max(500, _to_int(_deep_get(args, "max_events", conf["max_events"]), 20000)))
        conf["refresh"] = min(3600, max(0, _to_int(_deep_get(args, "refresh", conf["refresh"]), 0)))
        tab = str(_deep_get(args, "default_tab", conf.get("default_tab", "events")) or "events")
        if tab not in ("events", "online", "rank", "white"):
            tab = "events"
        conf["default_tab"] = tab
        days = _to_int(_deep_get(args, "default_days", conf.get("default_days", 3)), 3)
        if days not in (0, 1, 3, 7):
            days = 3
        conf["default_days"] = days
        th = str(_deep_get(args, "theme", conf.get("theme", "auto")) or "auto")
        if th not in ("auto", "light", "dark"):
            th = "auto"
        conf["theme"] = th
        conf["cidr_threshold"] = min(50, max(2, _to_int(_deep_get(args, "cidr_threshold", conf.get("cidr_threshold", 5)),
                                                       5)))
        self._conf = conf
        self._write_file(CONF_FILE, json.dumps(conf, ensure_ascii=False))
        return self._ok(conf)

    def lookup_ip(self, args=None):
        args = args or {}
        ip = str(_deep_get(args, "ip", "")).strip()
        if not re.match(r"^[0-9a-fA-F\.:]+$", ip):
            return self._err("IP 格式不正确")
        area = self._lookup_one(ip)
        if area:
            cache = {}
            raw = self._read_file(GEO_FILE)
            if raw:
                try:
                    cache = json.loads(raw)
                except Exception:
                    cache = {}
            cache[ip] = area
            self._write_file(GEO_FILE, json.dumps(cache, ensure_ascii=False))
        return self._ok({"ip": ip, "area": area or "未知"})

    def export_csv(self, args=None):
        args = args or {}
        data = self._collect()
        days = _to_int(_deep_get(args, "days", 3), 3)
        since = 0 if days <= 0 else _now() - days * 86400
        rows = self._filtered(data["events"], str(_deep_get(args, "status", "all")),
                              str(_deep_get(args, "keyword", "")),
                              str(_deep_get(args, "user", "")), since)
        lines = ["时间,用户,IP,源端口,状态,认证方式,时长(秒),数据源"]
        for e in rows:
            lines.append(",".join([
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(e["ts"])),
                e["user"] or "-", e["ip"] or "-", str(e["port"] or ""),
                STATUS_TEXT.get(e["status"], e["status"]),
                e.get("method", "") or "",
                str(e["duration"] or 0), e["src"],
            ]))
        return self._ok({"csv": "\r\n".join(lines), "count": len(rows)})

    def clean_cache(self, args=None):
        try:
            if os.path.exists(CACHE_FILE):
                os.remove(CACHE_FILE)
        except Exception:
            pass
        return self._ok({"msg": "已清理"})
