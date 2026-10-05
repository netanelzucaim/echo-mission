#!/usr/bin/env python3
"""Compatibility test: does the candidate image behave like nginx:1.25-bookworm?

Usage:
    python3 test/compat_test.py [--original IMAGE] [--candidate IMAGE]
                                [--only GROUP[,GROUP...]] [--list] [--keep] [-v]
    make test                      (candidate from the Makefile's IMAGE variable)

Boots the original image and the candidate as separate containers with identical
configuration, sends both the same requests, and compares status line, headers
(names, values and order) and body. Any difference that is not on the short,
documented list of allowed differences fails the run.

Exit code: 0 all checks match, 1 at least one mismatch, 2 the test could not run.

Needs Python 3.8+ (standard library only) and the docker CLI.
See test/README.md for what "working correctly" means and what is covered.
"""
import argparse, difflib, gzip, hashlib, json, os, re, shutil, socket, ssl, subprocess, sys, tempfile, time

ORIGINAL = "nginx:1.25-bookworm"
CANDIDATE = "echo-nginx:1.25-bookworm"
FIXED_MTIME = 1700000000          # every file the test copies in gets this mtime (2023-11-14)
HTTP_DATE = re.compile(r"^(Mon|Tue|Wed|Thu|Fri|Sat|Sun), \d{2} (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) "
                       r"\d{4} \d{2}:\d{2}:\d{2} GMT$")
ETAG = re.compile(r'^(W/)?"([0-9a-f]+)-([0-9a-f]+)"$')

# Header policies. Everything not named here must be byte-identical.
#   date       value must be a valid HTTP date on both sides; the instant is not compared
#   etag-size  nginx builds ETag as "<mtime hex>-<size hex>"; only the size part is compared
ANY = {"date": "date"}
# Files that ship inside the image (index.html, 50x.html) are packaged at different
# times in the two images, so their modification time legitimately differs.
PKGFILE = {"date": "date", "last-modified": "date", "etag": "etag-size"}

# Differences from the original that are deliberate. Each needs a reason, and the same
# reason is given in README.md. Anything else that differs is a failure.
ALLOWED = {
    "label:maintainer": "the image is rebuilt by its owner, not by NGINX, so the maintainer label names the owner",
}


class SetupError(Exception):
    pass


def run(cmd, check=True, input=None, timeout=120):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, input=input, timeout=timeout)
    if check and p.returncode != 0:
        raise SetupError(f"command failed ({p.returncode}): {' '.join(cmd)}\n{p.stderr.decode(errors='replace')}")
    return p


# --------------------------------------------------------------------------- HTTP

def parse_responses(data, methods):
    """Split a byte stream into HTTP responses. Returns a list of dicts."""
    out, i = [], 0
    for method in methods:
        if not data[i:i + 5] == b"HTTP/":
            if data[i:]:
                out.append({"raw": data[i:]})
            return out
        end = data.find(b"\r\n\r\n", i)
        if end < 0:
            out.append({"raw": data[i:]})
            return out
        lines = data[i:end].decode("latin-1").split("\r\n")
        headers = [tuple(part.strip() for part in line.split(":", 1)) if ":" in line else (line, "") for line in lines[1:]]
        hmap = {k.lower(): v for k, v in headers}
        status = int(lines[0].split()[1]) if len(lines[0].split()) > 1 and lines[0].split()[1].isdigit() else 0
        i = end + 4
        if method == "HEAD" or status in (204, 304) or 100 <= status < 200:
            body = b""
        elif hmap.get("transfer-encoding", "").lower() == "chunked":
            body = b""
            while True:
                nl = data.find(b"\r\n", i)
                if nl < 0:
                    break
                size = int(data[i:nl].split(b";")[0] or b"0", 16)
                i = nl + 2
                if size == 0:
                    i = data.find(b"\r\n\r\n", i - 2) + 4 if data.find(b"\r\n\r\n", i - 2) >= 0 else len(data)
                    break
                body += data[i:i + size]
                i += size + 2
        elif "content-length" in hmap:
            n = int(hmap["content-length"])
            body, i = data[i:i + n], i + n
        else:
            body, i = data[i:], len(data)
        out.append({"status_line": lines[0], "status": status, "headers": headers, "body": body})
    if data[i:]:
        out.append({"raw": data[i:]})
    return out


def render(responses, policy):
    """Normalised, human-readable text of a list of responses, used for comparison."""
    lines = []
    for n, r in enumerate(responses, 1):
        lines.append(f"--- response {n}")
        if "raw" in r:
            lines.append(f"(not an HTTP/1.x response) {len(r['raw'])} bytes sha256={hashlib.sha256(r['raw']).hexdigest()[:16]}")
            lines += r["raw"][:600].decode("latin-1").splitlines()
            continue
        lines.append(r["status_line"])
        encoding = ""
        for k, v in r["headers"]:
            mode = policy.get(k.lower(), "exact")
            if k.lower() == "content-encoding":
                encoding = v
            if mode == "date":
                v = "<valid HTTP date>" if HTTP_DATE.match(v) else f"<INVALID DATE: {v}>"
            elif mode == "etag-size":
                m = ETAG.match(v)
                v = f'{m.group(1) or ""}"<mtime>-{m.group(3)}"' if m else f"<UNEXPECTED ETAG: {v}>"
            lines.append(f"{k}: {v}")
        body = r["body"]
        lines.append(f"body: {len(body)} bytes sha256={hashlib.sha256(body).hexdigest()[:16]}")
        if encoding == "gzip" and body:
            try:
                plain = gzip.decompress(body)
                lines.append(f"body after gunzip: {len(plain)} bytes sha256={hashlib.sha256(plain).hexdigest()[:16]}")
            except OSError:
                lines.append("body after gunzip: <NOT VALID GZIP>")
        elif body and len(body) <= 1500:
            try:
                lines += ["| " + l for l in body.decode("utf-8").splitlines()]
            except UnicodeDecodeError:
                pass
    return "\n".join(lines)


# --------------------------------------------------------------------- containers

class Target:
    """One running container of one image."""

    def __init__(self, image, role, run_id):
        self.image, self.role, self.run_id = image, role, run_id
        self.name, self.ports = None, {}

    def start(self, group, files=None, ports=(80,)):
        self.name = f"compat-{self.run_id}-{group}-{self.role}"
        cmd = ["docker", "create", "--name", self.name]
        for p in ports:
            cmd += ["-p", f"127.0.0.1::{p}"]
        run(cmd + [self.image])
        for src, dest in files or []:
            run(["docker", "cp", src, f"{self.name}:{dest}"])
        run(["docker", "start", self.name])
        for p in ports:
            out = run(["docker", "port", self.name, f"{p}/tcp"]).stdout.decode().split()
            self.ports[p] = int(out[0].rsplit(":", 1)[1])
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                if self.http(b"GET /__ready HTTP/1.0\r\n\r\n", port=ports[0], timeout=2):
                    return
            except OSError:
                pass
            if run(["docker", "inspect", "-f", "{{.State.Running}}", self.name], check=False).stdout.strip() != b"true":
                break
            time.sleep(0.3)
        raise SetupError(f"{self.role} ({self.image}) did not start serving in group '{group}':\n{self.logs()[-1500:]}")

    def http(self, payload, port=80, timeout=20, tls=None):
        """Send raw bytes, return everything the server sends until it closes."""
        s = socket.create_connection(("127.0.0.1", self.ports[port]), timeout=timeout)
        try:
            if tls is not None:
                s = tls.wrap_socket(s, server_hostname="localhost")
            try:
                s.sendall(payload)
            except OSError:
                pass                                  # server closed early (for example 413); still read the reply
            chunks = []
            while True:
                try:
                    c = s.recv(65536)
                except (socket.timeout, ConnectionResetError, ssl.SSLError):
                    break
                if not c:
                    break
                chunks.append(c)
            return b"".join(chunks)
        finally:
            s.close()

    def logs(self):
        p = run(["docker", "logs", self.name], check=False)
        return (p.stdout + p.stderr).decode(errors="replace")

    def exec(self, *cmd):
        p = run(["docker", "exec", self.name, *cmd], check=False)
        return p.returncode, (p.stdout + p.stderr).decode(errors="replace")

    def stop(self, keep=False):
        if self.name and not keep:
            run(["docker", "rm", "-f", "-v", self.name], check=False)
        self.name = None


def image_sh(image, script):
    """Run a shell snippet in a throwaway container of the image; return (exit code, output)."""
    p = run(["docker", "run", "--rm", "--entrypoint", "sh", image, "-c", script], check=False)
    return p.returncode, (p.stdout + p.stderr).decode(errors="replace")


# ------------------------------------------------------------------------- runner

class Runner:
    def __init__(self, original, candidate, keep, verbose):
        self.orig = Target(original, "original", os.getpid())
        self.cand = Target(candidate, "candidate", os.getpid())
        self.keep, self.verbose = keep, verbose
        self.results = []                    # (group, name, outcome, detail)

    def record(self, group, name, a, b, expect=None, allowed=None):
        """Compare two rendered texts. expect: substring the ORIGINAL must contain (sanity check)."""
        if expect is not None and expect not in a:
            outcome = "BROKEN"
            detail = f"the original did not produce what this scenario is meant to exercise (expected '{expect}'):\n{a[:800]}"
        elif a == b:
            outcome, detail = "PASS", ""
        elif allowed:
            outcome, detail = "ALLOWED", f"{ALLOWED[allowed]}"
        else:
            outcome = "FAIL"
            detail = "\n".join(difflib.unified_diff(a.splitlines(), b.splitlines(), "original", "candidate", lineterm="", n=2))
        self.results.append((group, name, outcome, detail))
        mark = {"PASS": "PASS   ", "FAIL": "FAIL   ", "ALLOWED": "ALLOWED", "BROKEN": "BROKEN "}[outcome]
        print(f"  {mark} {name}")
        if outcome in ("FAIL", "BROKEN") or (self.verbose and detail):
            for line in detail.splitlines()[:60]:
                print(f"            {line}")

    def both(self, fn):
        return fn(self.orig), fn(self.cand)

    def request(self, group, name, payload, methods=("GET",), policy=ANY, port=80, expect=None, tls=None):
        def go(t):
            return render(parse_responses(t.http(payload, port=port, tls=tls), methods), policy)
        a, b = self.both(go)
        self.record(group, name, a, b, expect=expect)

    def start(self, group, files=None, ports=(80,)):
        print(f"\n[{group}]")
        self.orig.start(group, files, ports)
        self.cand.start(group, files, ports)

    def stop(self):
        self.orig.stop(self.keep)
        self.cand.stop(self.keep)


def get(path, extra="", version="1.1", method="GET"):
    host = "Host: localhost\r\n" if version == "1.1" else ""
    return f"{method} {path} HTTP/{version}\r\n{host}{extra}Connection: close\r\n\r\n".encode()


# ------------------------------------------------------------------------- groups

def group_image(r):
    """Image metadata and filesystem layout. No container is kept running."""
    g = "image"
    print(f"\n[{g}]")

    def cfg(t):
        c = json.loads(run(["docker", "inspect", t.image]).stdout)[0]["Config"]
        return c
    a, b = cfg(r.orig), cfg(r.cand)
    dump = lambda v: json.dumps(v, indent=1, sort_keys=True)
    for key in ("Entrypoint", "Cmd", "ExposedPorts", "StopSignal", "User", "WorkingDir", "Volumes"):
        r.record(g, f"config {key}", dump(a.get(key)), dump(b.get(key)))
    r.record(g, "config Env", dump(sorted(a.get("Env") or [])), dump(sorted(b.get("Env") or [])))
    la, lb = dict(a.get("Labels") or {}), dict(b.get("Labels") or {})
    r.record(g, "label maintainer", la.pop("maintainer", ""), lb.pop("maintainer", ""), allowed="label:maintainer")
    r.record(g, "other labels", dump(la), dump(lb))

    checks = [
        ("nginx user and group", "id nginx; getent passwd nginx; getent group nginx", "uid=101(nginx)"),
        ("nginx version", "nginx -v 2>&1", "nginx/1.25"),
        ("nginx configure arguments",
         # one flag per line; the compiler's source-path mapping depends on where the build ran
         "nginx -V 2>&1 | sed -n 's/^configure arguments: //p' | sed -E 's/ -ffile-prefix-map=[^ ]+//' | sed 's/ --/\\n--/g'",
         "--prefix=/etc/nginx"),
        ("file layout (path, type, mode, owner, link target)",
         "find /etc/nginx /usr/lib/nginx /usr/share/nginx /docker-entrypoint.d /docker-entrypoint.sh "
         "/var/cache/nginx /var/log/nginx /usr/sbin/nginx /usr/sbin/nginx-debug /etc/logrotate.d/nginx "
         "/usr/lib/systemd/system/nginx.service /usr/lib/systemd/system/nginx-debug.service 2>&1 "
         "-printf '%p %y %m %u:%g %l\\n' | sort", "/etc/nginx/nginx.conf"),
        ("content of config files, default pages and startup scripts",
         "find /etc/nginx /usr/share/nginx/html /docker-entrypoint.d /docker-entrypoint.sh -type f | sort | xargs sha256sum",
         "/etc/nginx/nginx.conf"),
        ("nginx -t on the shipped configuration", "nginx -t 2>&1; echo exit=$?", "exit=0"),
        ("nginx package registers default.conf as a conffile",
         "dpkg-query --show --showformat='${Conffiles}\\n' nginx | awk '{print $1}' | sort", "/etc/nginx/conf.d/default.conf"),
        ("helper tools present (envsubst, curl)", "command -v envsubst curl; echo exit=$?", "exit=0"),
        ("all four dynamic modules load",
         "cd /usr/lib/nginx/modules && ls *.so | grep -v debug | sort > /tmp/mods && "
         "{ sed 's|^|load_module modules/|; s|$|;|' /tmp/mods; echo 'events {} http { server { listen 8080; } }'; } > /tmp/m.conf && "
         "cat /tmp/mods && nginx -t -c /tmp/m.conf 2>&1 | sed 's|/tmp/m.conf|CONF|g'; echo exit=$?", "exit=0"),
    ]
    for name, script, expect in checks:
        (ca, oa), (cb, ob) = image_sh(r.orig.image, script), image_sh(r.cand.image, script)
        r.record(g, name, oa, ob, expect=expect)


def group_default(r):
    """The image exactly as shipped, no configuration added."""
    g = "default"
    r.start(g)
    try:
        strip = lambda t: "\n".join(l for l in t.logs().splitlines() if re.match(r"^(/docker-entrypoint\.sh|\d\d-[\w.-]+): ", l))
        a, b = r.both(strip)
        r.record(g, "startup script output", a, b, expect="ready for start up")

        def notices(t):  # nginx's own start-up lines, without timestamps, pids and kernel details
            keep = []
            for l in t.logs().splitlines():
                m = re.match(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[notice\] \d+#\d+: (.*)$", l)
                if m and not re.match(r"(OS:|getrlimit|start worker process|built by gcc)", m.group(1)):
                    keep.append(m.group(1))
            return "\n".join(keep)
        a, b = r.both(notices)
        r.record(g, "nginx start-up notices", a, b, expect="nginx/1.25")
        # The startup script adds an IPv6 listen line when the host has IPv6. Where it has
        # none the script skips that step on both sides, and the check says so in its name.
        ipv6 = "ipv6 not available" not in r.orig.logs()
        a, b = r.both(lambda t: t.exec("cat", "/etc/nginx/conf.d/default.conf")[1])
        r.record(g, "default.conf after start (IPv6 listen added)" if ipv6 else
                 "default.conf after start (no IPv6 on this host, so the IPv6 edit was NOT exercised)",
                 a, b, expect="listen  [::]:80;" if ipv6 else "listen       80;")

        r.request(g, "GET /", get("/"), policy=PKGFILE, expect="200 OK")
        r.request(g, "HEAD /", get("/", method="HEAD"), methods=("HEAD",), policy=PKGFILE, expect="200 OK")
        r.request(g, "GET /index.html", get("/index.html"), policy=PKGFILE, expect="200 OK")
        r.request(g, "GET /50x.html", get("/50x.html"), policy=PKGFILE, expect="200 OK")
        r.request(g, "GET / with a query string", get("/?a=1&b=two"), policy=PKGFILE, expect="200 OK")
        r.request(g, "GET / over HTTP/1.0 without Host", get("/", version="1.0"), policy=PKGFILE, expect="200 OK")
        r.request(g, "GET missing page", get("/does-not-exist"), expect="404 Not Found")
        r.request(g, "POST to a static page", get("/", extra="Content-Length: 5\r\n", method="POST") + b"hello", expect="405")
        r.request(g, "PUT", get("/x", extra="Content-Length: 1\r\n", method="PUT") + b"x", expect="405")
        r.request(g, "DELETE", get("/index.html", method="DELETE"), expect="405")
        r.request(g, "OPTIONS", get("/", method="OPTIONS"), expect="405")
        r.request(g, "unknown method", get("/", method="FROB"), expect="405")
        r.request(g, "Range: first 100 bytes", get("/", extra="Range: bytes=0-99\r\n"), policy=PKGFILE, expect="206 Partial Content")
        r.request(g, "Range: last 50 bytes", get("/", extra="Range: bytes=-50\r\n"), policy=PKGFILE, expect="206 Partial Content")
        r.request(g, "Range: two ranges (multipart)", get("/", extra="Range: bytes=0-9,20-29\r\n"),
                  policy=dict(PKGFILE, **{"content-type": "exact"}), expect="206 Partial Content")
        r.request(g, "Range: not satisfiable", get("/", extra="Range: bytes=999999-\r\n"), expect="416")
        r.request(g, "path traversal attempt", get("/../../etc/passwd"), expect="400 Bad Request")
        r.request(g, "encoded path", get("/index%2Ehtml"), policy=PKGFILE, expect="200 OK")
        r.request(g, "two requests on one keep-alive connection",
                  b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n" + get("/does-not-exist"),
                  methods=("GET", "GET"), policy=PKGFILE, expect="Connection: keep-alive")

        def conditional(t):  # each server is asked with its own validators
            first = parse_responses(t.http(get("/")), ("GET",))[0]
            h = dict((k.lower(), v) for k, v in first["headers"])
            inm = parse_responses(t.http(get("/", extra=f"If-None-Match: {h.get('etag', '')}\r\n")), ("GET",))
            ims = parse_responses(t.http(get("/", extra=f"If-Modified-Since: {h.get('last-modified', '')}\r\n")), ("GET",))
            old = parse_responses(t.http(get("/", extra="If-Modified-Since: Mon, 01 Jan 2001 00:00:00 GMT\r\n")), ("GET",))
            return render(inm + ims + old, PKGFILE)
        a, b = r.both(conditional)
        r.record(g, "conditional requests (If-None-Match, If-Modified-Since)", a, b, expect="304 Not Modified")

        # malformed and hostile requests
        r.request(g, "malformed: garbage instead of a request line", b"this is not http\r\n\r\n", expect="400 Bad Request")
        r.request(g, "malformed: HTTP/1.1 without Host", b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n", expect="400 Bad Request")
        r.request(g, "malformed: unsupported HTTP version", b"GET / HTTP/9.9\r\nHost: localhost\r\n\r\n", expect="505")
        r.request(g, "malformed: bad percent-encoding", get("/%zz"), expect="400 Bad Request")
        r.request(g, "malformed: header without colon", b"GET / HTTP/1.1\r\nHost: localhost\r\nbroken header line\r\nConnection: close\r\n\r\n")
        r.request(g, "malformed: space in header name", b"GET / HTTP/1.1\r\nHost: localhost\r\nBad Name: x\r\nConnection: close\r\n\r\n", expect="400 Bad Request")
        r.request(g, "malformed: negative Content-Length", get("/", extra="Content-Length: -5\r\n", method="POST"), expect="400 Bad Request")
        r.request(g, "malformed: two different Content-Length headers",
                  get("/", extra="Content-Length: 3\r\nContent-Length: 4\r\n", method="POST") + b"abc", expect="400 Bad Request")
        r.request(g, "malformed: Content-Length with Transfer-Encoding",
                  get("/", extra="Content-Length: 3\r\nTransfer-Encoding: chunked\r\n", method="POST") + b"0\r\n\r\n", expect="400 Bad Request")
        r.request(g, "malformed: unknown Transfer-Encoding", get("/", extra="Transfer-Encoding: bogus\r\n", method="POST"), expect="501")
        r.request(g, "malformed: null byte in the path", b"GET /a\x00b HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", expect="400 Bad Request")
        r.request(g, "too long: request line over 8k", get("/" + "a" * 9000), expect="414")
        r.request(g, "too long: one header over 8k", get("/", extra="X-Big: " + "b" * 9000 + "\r\n"), expect="400 Bad Request")
        r.request(g, "large body: 2 MB over the default 1 MB limit",
                  get("/", extra=f"Content-Length: {2 * 1024 * 1024}\r\n", method="POST") + b"x" * (2 * 1024 * 1024), expect="413")
        r.request(g, "empty connection (client sends nothing)", b"", methods=())

        def access_log(t):  # same requests were sent to both, so the access log must match too
            lines = [re.sub(r"\[\d\d/\w{3}/\d{4}:\d\d:\d\d:\d\d [+-]\d{4}\]", "[<time>]", l)
                     for l in t.logs().splitlines() if re.match(r"^\S+ - \S+ \[", l) and "/__ready" not in l]
            return "\n".join(l if len(l) < 300 else l[:120] + f" ...({len(l)} chars)... " + l[-80:] for l in lines)
        a, b = r.both(access_log)
        r.record(g, "access log lines for all requests above", a, b, expect='"GET / HTTP/1.1" 200')

        def error_log(t):   # error log lines, without timestamp, process id and connection number
            keep = []
            for l in t.logs().splitlines():
                m = re.match(r"^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d \[(error|warn|crit|alert|emerg)\] \d+#\d+: (\*\d+ )?(.*)$", l)
                if m and "/__ready" not in l:
                    keep.append(f"[{m.group(1)}] " + re.sub(r"client: [\d.]+", "client: <ip>", m.group(3))[:300])
            return "\n".join(keep)
        a, b = r.both(error_log)
        r.record(g, "error log lines for all requests above", a, b)

        def stop(t):
            start = time.time()
            run(["docker", "stop", "-t", "20", t.name], check=False, timeout=60)
            code = run(["docker", "inspect", "-f", "{{.State.ExitCode}}", t.name]).stdout.decode().strip()
            took = "under 5s" if time.time() - start < 5 else "5s or more"
            quit_line = "graceful shutdown logged" if "gracefully shutting down" in t.logs() else "no graceful shutdown line"
            return f"exit code {code}, {took}, {quit_line}"
        a, b = r.both(stop)
        r.record(g, "docker stop (SIGQUIT, graceful shutdown)", a, b, expect="exit code 0")
    finally:
        r.stop()


CUSTOM_CONF = r"""
# compatibility-test configuration: the same file is copied into both containers
gzip on;
gzip_types text/plain application/json;
gzip_min_length 200;

server {
    listen 80;
    listen 443 ssl;
    http2 on;
    server_name localhost;
    ssl_certificate     /etc/nginx/test/cert.pem;
    ssl_certificate_key /etc/nginx/test/key.pem;

    root /srv/site;
    error_page 404 /custom404.html;
    add_header X-Compat-Test "yes" always;

    location = /teapot      { default_type text/plain; return 418 "I am a teapot\n"; }
    location = /redirect    { return 301 /moved-here; }
    location = /rewrite     { rewrite ^ /hello.txt last; }
    # exercises the ngx_http_rewrite_module path fixed by the CVE-2026-42945 backport:
    # a capture used in a later directive after a rewrite replacement that has arguments.
    location /rwcap         { rewrite ^(.*)$ /dest?c=1; set $cap $1; default_type text/plain; return 200 "cap=$cap\n"; }
    location /files/        { autoindex on; }
    location /fallback/     { try_files $uri /hello.txt; }
    location /headers       { default_type text/plain; return 200 "ua=$http_user_agent\nxff=$http_x_forwarded_for\nargs=$args\n"; }
    location /private/      { auth_basic "restricted"; auth_basic_user_file /etc/nginx/test/htpasswd; }
    location /proxy/        { proxy_pass http://127.0.0.1:8081/; proxy_set_header X-From-Proxy "1"; }
    location /upload        { client_max_body_size 8m; proxy_pass http://127.0.0.1:8081/echo; }
    location /sub           { default_type text/html; sub_filter "World" "nginx"; sub_filter_once off; alias /srv/site/hello.html; }
}

server {
    listen 127.0.0.1:8081;
    client_max_body_size 0;
    location /       { default_type application/json; add_header X-Backend "yes"; return 200 '{"backend":"$request_uri","from_proxy":"$http_x_from_proxy"}\n'; }
    location /echo   { default_type text/plain; return 200 "received $content_length bytes\n"; }
}
"""


def group_custom(r, work):
    """A user-supplied configuration: static site, proxying, TLS, auth, compression, large bodies."""
    g = "custom"
    site, conf, extra = os.path.join(work, "site"), os.path.join(work, "conf.d"), os.path.join(work, "test")
    for d in (site, conf, extra, os.path.join(site, "files"), os.path.join(site, "private")):
        os.makedirs(d)
    write = lambda path, data: open(path, "wb").write(data if isinstance(data, bytes) else data.encode())
    write(os.path.join(site, "hello.txt"), "Hello from the compatibility test\n")
    write(os.path.join(site, "hello.html"), "<html><body>Hello World, World!</body></html>\n")
    write(os.path.join(site, "custom404.html"), "<html><body>custom not-found page</body></html>\n")
    write(os.path.join(site, "data.json"), json.dumps({"items": [{"id": i, "name": f"item-{i}"} for i in range(200)]}))
    write(os.path.join(site, "big.txt"), ("line of text that compresses well\n" * 4000))
    write(os.path.join(site, "blob.bin"), hashlib.sha256(b"seed").digest() * 32768)      # 1 MiB, fixed content
    write(os.path.join(site, "files", "a.txt"), "a\n")
    write(os.path.join(site, "files", "b with space.txt"), "b\n")
    write(os.path.join(site, "private", "secret.txt"), "the secret\n")
    write(os.path.join(conf, "default.conf"), CUSTOM_CONF)

    # Certificate and password hashes are made once, with the ORIGINAL image's openssl, and used by both.
    code, pem = image_sh(r.orig.image, "openssl req -x509 -newkey rsa:2048 -nodes -keyout /tmp/k -out /tmp/c "
                                       "-subj /CN=localhost -days 3 >/dev/null 2>&1 && cat /tmp/k /tmp/c")
    if code != 0 or "BEGIN CERTIFICATE" not in pem:
        raise SetupError("could not create a test certificate with the original image's openssl")
    cut = pem.index("-----BEGIN CERTIFICATE-----")
    write(os.path.join(extra, "key.pem"), pem[:cut])
    write(os.path.join(extra, "cert.pem"), pem[cut:])
    _, apr1 = image_sh(r.orig.image, "openssl passwd -apr1 -salt compat12 s3cret")
    _, sha512 = image_sh(r.orig.image, "openssl passwd -6 -salt compatsalt s3cret")
    write(os.path.join(extra, "htpasswd"), f"alice:{apr1.strip()}\nbob:{sha512.strip()}\n")
    for root, dirs, files in os.walk(work):
        for n in dirs + files:
            os.chmod(os.path.join(root, n), 0o755 if n in dirs else 0o644)
            os.utime(os.path.join(root, n), (FIXED_MTIME, FIXED_MTIME))

    r.start(g, files=[(site, "/srv/site"), (os.path.join(conf, "default.conf"), "/etc/nginx/conf.d/default.conf"),
                      (extra, "/etc/nginx/test")], ports=(80, 443))
    try:
        ipv6 = "ipv6 not available" not in r.orig.logs()
        a, b = r.both(lambda t: "\n".join(l for l in t.logs().splitlines() if "10-listen-on-ipv6" in l))
        r.record(g, "startup scripts leave a user-supplied default.conf alone" if ipv6 else
                 "startup script output with a user-supplied default.conf (no IPv6 on this host)",
                 a, b, expect="differs from the packaged version" if ipv6 else "10-listen-on-ipv6-by-default.sh")
        # files copied in by the test have the same mtime on both sides, so validators must match exactly
        r.request(g, "static text file", get("/hello.txt"), expect="200 OK")
        r.request(g, "static binary file, 1 MiB", get("/blob.bin"), expect="200 OK")
        r.request(g, "MIME type for .json", get("/data.json"), expect="application/json")
        r.request(g, "gzip: compressible text", get("/big.txt", extra="Accept-Encoding: gzip\r\n"), expect="Content-Encoding: gzip")
        r.request(g, "gzip: JSON", get("/data.json", extra="Accept-Encoding: gzip\r\n"), expect="Content-Encoding: gzip")
        r.request(g, "gzip: not requested", get("/big.txt"), expect="200 OK")
        r.request(g, "return with a custom status", get("/teapot"), expect="418")
        r.request(g, "redirect with Location", get("/redirect"), expect="301 Moved Permanently")
        r.request(g, "directory without trailing slash redirects", get("/files"), expect="301 Moved Permanently")
        r.request(g, "internal rewrite", get("/rewrite"), expect="200 OK")
        r.request(g, "rewrite capture reused after a replacement with args (CVE-2026-42945 path)",
                  get("/rwcap/abcdef"), expect="cap=/rwcap/abcdef")
        r.request(g, "try_files fallback", get("/fallback/nothing-here"), expect="200 OK")
        r.request(g, "directory listing (autoindex)", get("/files/"), expect="b with space.txt")
        r.request(g, "custom error page", get("/no-such-page"), expect="custom not-found page")
        r.request(g, "request headers reach variables",
                  get("/headers?x=1", extra="User-Agent: compat-test/1.0\r\nX-Forwarded-For: 203.0.113.9\r\n"), expect="ua=compat-test/1.0")
        r.request(g, "response body rewriting (sub_filter)", get("/sub"), expect="Hello nginx, nginx!")
        r.request(g, "basic auth: no credentials", get("/private/secret.txt"), expect="401 Unauthorized")
        r.request(g, "basic auth: wrong password", get("/private/secret.txt", extra="Authorization: Basic YWxpY2U6d3Jvbmc=\r\n"), expect="401 Unauthorized")
        r.request(g, "basic auth: correct password (apr1 hash)", get("/private/secret.txt", extra="Authorization: Basic YWxpY2U6czNjcmV0\r\n"), expect="200 OK")
        r.request(g, "basic auth: correct password (SHA-512 crypt, libcrypt)", get("/private/secret.txt", extra="Authorization: Basic Ym9iOnMzY3JldA==\r\n"), expect="200 OK")
        r.request(g, "reverse proxy to a backend", get("/proxy/some/path?q=1"), expect='"from_proxy":"1"')
        for mb, want in ((1, "200 OK"), (5, "200 OK"), (9, "413")):
            n = mb * 1024 * 1024
            r.request(g, f"large body: {mb} MB upload through the proxy (limit 8 MB)",
                      get("/upload", extra=f"Content-Length: {n}\r\n", method="POST") + b"u" * n, expect=want)
        r.request(g, "chunked request body",
                  get("/upload", extra="Transfer-Encoding: chunked\r\n", method="POST") + b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n", expect="received 11 bytes")

        def handshake(t):
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
            ctx.set_alpn_protocols(["h2", "http/1.1"])
            with socket.create_connection(("127.0.0.1", t.ports[443]), timeout=15) as raw:
                with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                    return f"protocol {s.version()}, cipher {s.cipher()[0]}, ALPN {s.selected_alpn_protocol()}"
        a, b = r.both(handshake)
        r.record(g, "TLS handshake (protocol, cipher, HTTP/2 offered via ALPN)", a, b, expect="ALPN h2")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        ctx.set_alpn_protocols(["http/1.1"])
        r.request(g, "HTTPS request", get("/hello.txt"), port=443, tls=ctx, expect="200 OK")
        ctx12 = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx12.check_hostname, ctx12.verify_mode = False, ssl.CERT_NONE
        ctx12.maximum_version = ssl.TLSVersion.TLSv1_2

        def tls12(t):
            with socket.create_connection(("127.0.0.1", t.ports[443]), timeout=15) as raw:
                with ctx12.wrap_socket(raw, server_hostname="localhost") as s:
                    return f"protocol {s.version()}, cipher {s.cipher()[0]}"
        a, b = r.both(tls12)
        r.record(g, "TLS 1.2 handshake", a, b, expect="TLSv1.2")
        r.request(g, "plain HTTP sent to the HTTPS port", get("/"), port=443, expect="400")

        def reload(t):  # drop the timestamp and process id from nginx's message
            code, out = t.exec("nginx", "-s", "reload")
            return f"exit={code}\n" + re.sub(r"(?m)^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d (\[\w+\]) \d+#\d+: ", r"\1 ", out)
        a, b = r.both(reload)
        r.record(g, "nginx -s reload", a, b, expect="exit=0")
        time.sleep(1)
        r.request(g, "still serving after reload", get("/hello.txt"), expect="200 OK")
    finally:
        r.stop()


GROUPS = {
    "image": "image settings and filesystem layout",
    "default": "the image as shipped: default site, error handling, malformed requests, shutdown",
    "custom": "a user-supplied configuration: static files, gzip, proxy, large bodies, auth, TLS, reload",
}


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--original", default=os.environ.get("ORIGINAL", ORIGINAL))
    ap.add_argument("--candidate", default=os.environ.get("CANDIDATE", CANDIDATE))
    ap.add_argument("--only", default="", help="comma-separated groups to run (default: all)")
    ap.add_argument("--list", action="store_true", help="list the groups and exit")
    ap.add_argument("--keep", action="store_true", help="leave the containers running for inspection")
    ap.add_argument("-v", "--verbose", action="store_true")
    a = ap.parse_args()
    if a.list:
        for k, v in GROUPS.items():
            print(f"{k:8} {v}")
        return 0
    only = [x for x in a.only.split(",") if x] or list(GROUPS)
    unknown = [x for x in only if x not in GROUPS]
    if unknown:
        print(f"unknown group: {', '.join(unknown)}", file=sys.stderr)
        return 2
    if not shutil.which("docker"):
        print("ERROR: docker not found in PATH", file=sys.stderr)
        return 2
    for image in (a.original, a.candidate):
        if run(["docker", "image", "inspect", image], check=False).returncode != 0:
            if run(["docker", "pull", image], check=False, timeout=600).returncode != 0:
                print(f"ERROR: image not available: {image}", file=sys.stderr)
                return 2

    print(f"original:  {a.original}\ncandidate: {a.candidate}")
    r = Runner(a.original, a.candidate, a.keep, a.verbose)
    work = tempfile.mkdtemp(prefix="compat-")
    try:
        if "image" in only:
            group_image(r)
        if "default" in only:
            group_default(r)
        if "custom" in only:
            group_custom(r, work)
    except SetupError as e:
        print(f"\nERROR: the test could not run: {e}", file=sys.stderr)
        r.stop()
        return 2
    finally:
        shutil.rmtree(work, ignore_errors=True)

    count = lambda o: sum(1 for x in r.results if x[2] == o)
    print(f"\n{len(r.results)} checks: {count('PASS')} match, {count('ALLOWED')} allowed difference, "
          f"{count('FAIL')} mismatch, {count('BROKEN')} broken scenario")
    for group, name, outcome, detail in r.results:
        if outcome == "ALLOWED":
            print(f"  allowed: {group}/{name}: {detail}")
    bad = [x for x in r.results if x[2] in ("FAIL", "BROKEN")]
    if bad:
        print("\nNOT a drop-in replacement. Mismatches:")
        for group, name, outcome, _ in bad:
            print(f"  {outcome}: {group}/{name}")
        return 1
    print("\nThe candidate behaves like the original for every scenario tested.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
