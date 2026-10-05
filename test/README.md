# Compatibility test

Proves that the patched image can replace `nginx:1.25-bookworm` without anyone
noticing, except that it has fewer vulnerabilities.

```sh
make test                                   # candidate = the Makefile's IMAGE
python3 test/compat_test.py --candidate <image>
python3 test/compat_test.py --only default  # one group; --list shows the groups
```

Needs Python 3.8 or newer (standard library only) and Docker. It takes about one
minute. Exit code 0 means every check matched, 1 means at least one mismatch, 2 means
the test could not run.

## What "working correctly" means

The test does not check that nginx is correct in the abstract. It checks one thing:
**for the same input, the candidate answers exactly as the original does.** The
original image is the specification.

For every request the two containers must return the same:

- **status line**, for example `HTTP/1.1 404 Not Found`;
- **headers**: the same names, the same values, in the same order;
- **body**, byte for byte.

They must also match in what surrounds the requests: the image settings, the files on
disk, the startup output, the access and error log lines, and how the container stops.

### The only values allowed to differ

A few values depend on the moment or on when a file was packaged. They cannot be
equal, so the test checks their form and ignores the rest.

| Value | Why it differs | What is still checked |
|---|---|---|
| `Date` header | It is the current time | It is present and a valid HTTP date |
| `Last-Modified` of files shipped in the image (`index.html`, `50x.html`) | The file was packaged at a different time in each image | It is present and a valid HTTP date |
| `ETag` of those same files | nginx builds it from modification time and size | The size part is identical |
| Timestamps, process ids and connection numbers in log lines | They change on every run | The rest of each line is identical |

Files that the test copies into both containers get the same modification time, so for
those `Last-Modified` and `ETag` must match exactly.

One difference in the image itself is deliberate and listed in the code (`ALLOWED`):
the `maintainer` label, which names the person who rebuilt the image and not NGINX.
It is reported as "allowed", not as a pass. Anything else that differs fails the run.

### Guard against empty passes

Two broken servers that both return an error would "match". To prevent that, most
scenarios also state what the original must return, for example `413` for an oversized
body. If the original does not return it, the scenario is reported as BROKEN and the
run fails, because the test is then not exercising what it claims to.

## What the test covers

91 checks in three groups. Each group starts both images as separate containers with
identical configuration.

### `image`: settings and files, nothing running

| Check | Why it matters |
|---|---|
| Entrypoint, command, exposed port, stop signal, user, working directory, volumes, environment, labels | These are what the assignment names: a `docker run` or Kubernetes manifest written for the original must keep working |
| `nginx` user and group ids | Mounted volumes and file permissions depend on uid/gid 101 |
| nginx version and configure arguments | Same features compiled in, same default paths |
| File layout under `/etc/nginx`, the modules folder, the default site, the startup scripts, log and cache folders: path, type, permissions, owner, link target | Configs and mounts refer to these paths |
| Content of the config files, default pages and startup scripts | The default behaviour comes from these files |
| `nginx -t` on the shipped configuration | The image starts |
| The `nginx` package registers `default.conf` as a config file | The IPv6 startup script depends on it |
| `envsubst` and `curl` are present | The template startup script and common health checks use them |
| All four dynamic modules load | A config with `load_module` for xslt, geoip, image-filter or njs must still start |

### `default`: the image exactly as shipped

| Area | Scenarios |
|---|---|
| Startup | Output of the startup scripts, nginx's start-up notices, `default.conf` after start |
| Normal requests | `GET /`, `HEAD /`, `/index.html`, `/50x.html`, query string, HTTP/1.0 without `Host`, encoded path, two requests on one keep-alive connection |
| Errors | Missing page (404); `POST`, `PUT`, `DELETE`, `OPTIONS` and an unknown method on a static page (405) |
| Caching | `If-None-Match` and `If-Modified-Since`, each server asked with its own validators (304), and a stale date (200) |
| Ranges | First bytes, last bytes, two ranges (multipart), unsatisfiable range (416) |
| Malformed requests | Garbage instead of a request line, HTTP/1.1 without `Host`, unsupported HTTP version, bad percent-encoding, header without a colon, space in a header name, negative `Content-Length`, two different `Content-Length` headers, `Content-Length` together with `Transfer-Encoding`, unknown `Transfer-Encoding`, null byte in the path, path traversal, a connection that sends nothing |
| Size limits | Request line over 8 KB (414), one header over 8 KB (400), a 2 MB body against the default 1 MB limit (413) |
| Logs | Access log and error log lines produced by all of the above |
| Shutdown | `docker stop`: exit code 0, quick, graceful shutdown logged |

### `custom`: a configuration a user would bring

The test copies in a site, a server configuration, a TLS certificate and a password
file. The certificate and the password hashes are created once, with the original
image's own `openssl`, and the same files go into both containers.

| Area | Scenarios |
|---|---|
| Static files | Text, a 1 MiB binary file, MIME type for `.json`, directory listing, redirect for a directory without a trailing slash |
| Compression | gzip for text and JSON (compressed bytes and the decompressed content), and no gzip when not requested |
| Rewriting | `return` with a custom status, redirect with `Location`, internal `rewrite`, `try_files` fallback, custom error page, `add_header`, `sub_filter` |
| Variables | Request headers and query string reaching nginx variables |
| Authentication | Basic auth without credentials, with a wrong password, and with correct passwords stored as an `apr1` hash and as a SHA-512 `crypt` hash (the second goes through `libcrypt`) |
| Reverse proxy | A request proxied to a backend, with an added request header |
| Large and streamed bodies | 1 MB and 5 MB uploads accepted and a 9 MB upload rejected against an 8 MB limit, all through the proxy so the body is really read and buffered to disk; a chunked request body |
| TLS | Handshake protocol and cipher with HTTP/2 offered through ALPN, a TLS 1.2 handshake, an HTTPS request, plain HTTP sent to the HTTPS port |
| Operations | `nginx -s reload`, and serving again afterwards |

## What the test does not cover

Stated plainly, so nobody reads a pass as more than it is.

- **HTTP/2 and HTTP/3 request handling.** The test checks that HTTP/2 is offered in
  the TLS handshake. It does not send HTTP/2 frames or use QUIC; Python's standard
  library cannot.
- **What the modules do.** It checks that the four dynamic modules load. It does not
  resize an image, run an XSLT transform, look up a GeoIP database or run njs code.
- **The mp4 module.** No MP4 file is served. This matters because the planned backport
  (CVE-2024-7347) is in that module. A scenario that serves a small MP4 with `?start=`
  should be added together with the patch.
- **The mail and stream (TCP/UDP) proxies**, FastCGI, uwsgi, SCGI and gRPC upstreams,
  WebSocket upgrades, and caching (`proxy_cache`).
- **Performance and resource use.** Nothing is measured: not latency, not memory, not
  behaviour under load or with many connections.
- **IPv6**, when the machine running the test has none. The check's name says so when
  that happens, because the startup script then skips its IPv6 step on both sides.
- **Other platforms.** It tests the image for the architecture Docker runs natively.
- **Security.** A matching response does not show that a vulnerability is fixed. That
  is the job of the patch, its own regression test, and the scan comparison.

## How it was checked

Run against the real patched image on 2026-10-05: **92 checks, 91 match, 1 allowed
difference (the `maintainer` label), 0 mismatch** — a verified drop-in.

The test itself was also validated so a false "match" cannot slip through:

| Candidate | Expected | Result |
|---|---|---|
| The original image against itself | Everything matches | all match, exit code 0 |
| The original with a changed `index.html`, `server_tokens off` and another `maintainer` label | Fails | 63 mismatches, the label reported as allowed, exit code 1 |

## How it works

- Each container is created, files are copied in with `docker cp`, and then it is
  started. Ports are published on random `127.0.0.1` ports, so nothing clashes with
  other services and the test does not depend on bind mounts.
- Requests are written as raw bytes on a socket. That is what makes malformed requests
  possible, and it keeps header order and exact bytes visible.
- Responses are parsed, the few time-dependent values are normalised as described
  above, and the two results are compared as text. A mismatch prints a diff.
- Containers are removed at the end, also on failure. `--keep` leaves them running
  for inspection.

## Adding a scenario

Add one line to the matching group in `compat_test.py`:

```python
r.request(g, "what it tests", get("/path", extra="Header: value\r\n"), expect="200 OK")
```

`expect` is a piece of text the original's response must contain. Use the `PKGFILE`
policy only for files that ship inside the image.
