# Startup scripts

These files were extracted unchanged from `nginx:1.25-bookworm` so that the patched
image starts exactly like the original. The `Containerfile` copies
`docker-entrypoint.sh` to `/` and the `docker-entrypoint.d/` folder to
`/docker-entrypoint.d/`. This README is not copied into the image.

## How they run

`docker-entrypoint.sh` is the image's entrypoint. When the container command is
`nginx` (the default), it runs every script in `/docker-entrypoint.d/` in name order,
which is why the names start with numbers, and then starts nginx.

- `*.sh` files are executed.
- `*.envsh` files are sourced, so they can export variables to the scripts after them.
- Files without the executable bit are skipped with a log line.
- Setting `NGINX_ENTRYPOINT_QUIET_LOGS` silences the log lines.

## The four scripts

| Script | What it does | Runs by default? |
|---|---|---|
| `10-listen-on-ipv6-by-default.sh` | Edits `/etc/nginx/conf.d/default.conf` so nginx also listens on IPv6 (`listen [::]:80;`) | Yes |
| `15-local-resolvers.envsh` | Reads the DNS servers from `/etc/resolv.conf` and exports them as `NGINX_LOCAL_RESOLVERS` | Only if `NGINX_ENTRYPOINT_LOCAL_RESOLVERS` is set |
| `20-envsubst-on-templates.sh` | Fills environment variables into the templates in `/etc/nginx/templates/` and writes the results to `/etc/nginx/conf.d/` | Only if the templates folder exists |
| `30-tune-worker-processes.sh` | Sets `worker_processes` in `nginx.conf` to match the container's CPU limit | Only if `NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE` is set |

On a plain `docker run`, only the first script changes anything.

## What these scripts require from the build

Two of the scripts depend on things outside this folder. If they are missing, the
scripts do not fail; they skip silently, and the image then behaves differently from
the original.

### The package must be named `nginx` and own `default.conf` as a conffile

Before editing the file, `10-listen-on-ipv6-by-default.sh` checks that it is still
the packaged version:

```sh
dpkg-query --show --showformat='${Conffiles}\n' nginx | grep etc/nginx/conf.d/default.conf
```

It compares that checksum with the file on disk and exits without changes if they
differ or if nothing is found. So the `.deb` built in `build/` must:

- be named exactly `nginx`, and
- list `/etc/nginx/conf.d/default.conf` in its `conffiles`, so dpkg records a checksum.

Otherwise the patched image listens on IPv4 only while the original listens on IPv4
and IPv6. The compatibility test should cover this.

The edit itself is a `sed` that looks for the exact text `listen       80;`. If
`default.conf` is spaced differently, nothing is replaced, so the file's content has
to match the original's too.

### `envsubst` must be installed

`20-envsubst-on-templates.sh` calls `envsubst`, which comes from the `gettext-base`
package. The original image keeps that package installed for this reason, and the
`Containerfile` installs it as well.
