# -*- coding: utf-8 -*-
"""生成用于本地调试的 sshd 日志样本（格式覆盖 Debian ISO / CentOS syslog）"""
import os
import random
import time
import datetime

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "fake_logs")
random.seed(20261116)

HOSTS = ["BT-Server", "Debian-TXGZ"]


def iso(ts, tz="+08:00"):
    d = datetime.datetime.fromtimestamp(ts)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + "%06d" % (ts % 1000000) + tz


def syslog(ts):
    d = datetime.datetime.fromtimestamp(ts)
    return d.strftime("%b %d %H:%M:%S")


def pid():
    return random.randint(20000, 990000)


def line(ts, fmt, host, prog, p, msg):
    head = iso(ts) if fmt == "iso" else syslog(ts)
    return "%s %s %s[%d]: %s" % (head, host, prog, p, msg)


def main():
    if not os.path.isdir(OUT):
        os.makedirs(OUT)
    now = int(time.time())
    out = []

    # 1) 正常登录（成功 + 会话时长）
    good_users = ["root", "deploy", "www"]
    good_ips = ["103.116.245.55", "106.55.203.79", "2402:4e00::8cc0"]
    for i in range(26):
        ts = now - random.randint(600, 3 * 86400)
        fmt = "iso" if i % 3 else "sys"
        host = random.choice(HOSTS)
        prog = "sshd-session" if fmt == "iso" else "sshd"
        p = pid()
        u = random.choice(good_users)
        ip = random.choice(good_ips)
        port = random.randint(30000, 65000)
        method = random.choice(["publickey", "password"])
        extra = " ssh2: ED25519 SHA256:HvOVNLW6NEzA77WSniOCCJ710FUkRwaQx56zDkF8Btc" if method == "publickey" else " ssh2"
        out.append(line(ts, fmt, host, prog, p, "Accepted %s for %s from %s port %d%s" % (method, u, ip, port, extra)))
        out.append(line(ts + 1, fmt, host, prog, p,
                        "pam_unix(sshd:session): session opened for user %s(uid=0) by %s(uid=0)" % (u, u)))
        close = ts + random.choice([8, 32, 95, 400, 3600, 9000])
        out.append(line(close, fmt, host, prog, p, "Disconnected from user %s %s port %d" % (u, ip, port)))
        out.append(line(close, fmt, host, prog, p, "pam_unix(sshd:session): session closed for user %s" % u))

    # 2) 爆破（无效用户 / 密码错误 / 超限）
    bad_ips = ["129.212.186.114", "45.148.10.92", "185.243.115.84", "212.70.149.71",
               "45.148.10.93", "45.148.10.94", "45.148.10.95", "45.148.10.96",
               "129.212.186.115", "129.212.186.116"]
    names = ["root", "admin", "test", "oracle", "ubnt", "user", "roo", "postgres", "ftpuser", "www"]
    for i in range(260):
        ts = now - random.randint(60, 30 * 3600)
        fmt = "iso" if i % 4 else "sys"
        host = random.choice(HOSTS)
        prog = "sshd-session" if fmt == "iso" else "sshd"
        p = pid()
        ip = random.choice(bad_ips)
        port = random.randint(32768, 65000)
        u = random.choice(names)
        r = random.random()
        if r < 0.45:
            out.append(line(ts, fmt, host, prog, p, "Invalid user %s from %s port %d" % (u, ip, port)))
        elif r < 0.85:
            invalid = "invalid user " if u not in ("root", "www") and random.random() < 0.5 else ""
            out.append(line(ts, fmt, host, prog, p,
                            "Failed password for %s%s from %s port %d ssh2" % (invalid, u, ip, port)))
        elif r < 0.95:
            out.append(line(ts, fmt, host, prog, p,
                            "Failed publickey for %s from %s port %d ssh2: RSA SHA256:abcd" % (u, ip, port)))
        else:
            out.append(line(ts, fmt, host, prog, p,
                            "error: maximum authentication attempts exceeded for %s from %s port %d ssh2 [preauth]" % (u, ip, port)))

        if random.random() < 0.18:
            out.append(line(ts + 2, fmt, host, prog, p,
                            "Connection closed by authenticating user %s %s port %d [preauth]" % (u, ip, port)))

    # 3) 无关噪音行（应被忽略）
    out.append(line(now - 300, "iso", HOSTS[1], "sshd", 1234, "Server listening on 0.0.0.0 port 22996."))
    out.append(line(now - 299, "iso", HOSTS[1], "sshd-session", 1235, "rexec line 126: Deprecated option RSAAuthentication [preauth]"))
    out.append(line(now - 298, "iso", HOSTS[1], "cron", 1236, "pam_unix(cron:session): session opened for user root"))

    out.sort(key=lambda x: (x[:26]))
    with open(os.path.join(OUT, "auth.log"), "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")
    print("wrote %d lines -> %s" % (len(out), OUT))


if __name__ == "__main__":
    main()
