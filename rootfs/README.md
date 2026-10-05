# rootfs/: files copied unchanged from the original image

Everything here was extracted with `docker cp` from `nginx:1.25-bookworm` and is copied
into the new image at the same path, so the new image starts and looks exactly like the
original. The folder mirrors the image: `rootfs/X` goes to `/X`. This README is not
copied. (The original's other leftover, nginx.org's apt signing key, is not stored here:
the `Containerfile` fetches it the same way the original's build did.)

| File | Goes to | Mode | Why it is here |
|---|---|---|---|
| `docker-entrypoint.sh` | `/docker-entrypoint.sh` | 0755 | The image's entrypoint |
| `docker-entrypoint.d/*` | `/docker-entrypoint.d/` | 0755 | The four startup scripts it runs |

## Rules

- **Do not edit these files.** The drop-in claim depends on them being byte-identical to
  the original. If one has to change, record it in `docs/image-config.md` as a deliberate
  difference.
- **Refresh them only from the original image** (`docker cp`), never from the internet.
- **Keep the executable bit on the scripts.** The entrypoint skips non-executable scripts
  with only a log line. The `Containerfile` also sets the modes when copying.
- **Keep this README outside `docker-entrypoint.d/`.** The entrypoint would log it as an
  ignored file, which would change the startup output.

## How the startup scripts run

`docker-entrypoint.sh` is the image's entrypoint. When the container command is `nginx`
(the default), it runs every script in `/docker-entrypoint.d/` in name order, then starts
nginx. `*.sh` files are executed, `*.envsh` files are sourced (so they can export
variables), files without the executable bit are skipped, and
`NGINX_ENTRYPOINT_QUIET_LOGS` silences the log lines.

| Script | What it does | Runs by default? |
|---|---|---|
| `10-listen-on-ipv6-by-default.sh` | Edits `/etc/nginx/conf.d/default.conf` so nginx also listens on IPv6 (`listen [::]:80;`) | Yes |
| `15-local-resolvers.envsh` | Exports the DNS servers from `/etc/resolv.conf` as `NGINX_LOCAL_RESOLVERS` | Only if `NGINX_ENTRYPOINT_LOCAL_RESOLVERS` is set |
| `20-envsubst-on-templates.sh` | Fills environment variables into `/etc/nginx/templates/` and writes the results to `/etc/nginx/conf.d/` | Only if the templates folder exists |
| `30-tune-worker-processes.sh` | Sets `worker_processes` to match the container's CPU limit | Only if `NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE` is set |

On a plain `docker run`, only the first script changes anything.

## What the scripts require from the build

If these are missing the scripts do not fail; they skip silently, and the image then
behaves differently from the original.

- **The package must be named `nginx` and own `default.conf` as a conffile.** Before
  editing, `10-listen-on-ipv6-by-default.sh` checks the file is still the packaged
  version:
  `dpkg-query --show --showformat='${Conffiles}\n' nginx | grep etc/nginx/conf.d/default.conf`.
  It compares that checksum with the file on disk and does nothing if they differ or
  nothing is found. The edit itself is a `sed` looking for the exact text
  `listen       80;`, so the file's content must match the original's too. The
  compatibility test checks both the conffile and the result after start.
- **`envsubst` must be installed.** `20-envsubst-on-templates.sh` needs it; it comes from
  the `gettext-base` package, which the `Containerfile` installs, as the original does.
