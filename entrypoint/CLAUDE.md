# entrypoint/

Startup scripts extracted unchanged from `nginx:1.25-bookworm`. Read `README.md` in
this folder for what each one does.

## Rules

- Do not edit these scripts. The image must start exactly like the original, and the
  compatibility claim depends on them being byte-identical. If one has to change, record
  it in the root `README.md` as a deliberate difference.
- To refresh them, extract again from the original image with `docker cp`; do not copy
  from the internet.
- Keep the executable bit. The entrypoint skips non-executable scripts with only a log
  line. The `Containerfile` also sets `--chmod=0755` when copying.
- Only `docker-entrypoint.sh` and `docker-entrypoint.d/` go into the image. `README.md`
  and this file do not, so do not move them into `docker-entrypoint.d/`: the entrypoint
  would log them as ignored files, which differs from the original's startup output.

## Constraints these scripts put on the build

- The package must be named `nginx` and list `/etc/nginx/conf.d/default.conf` as a
  conffile, with the original's exact content (including `listen       80;`).
  Otherwise `10-listen-on-ipv6-by-default.sh` silently skips enabling IPv6.
- `gettext-base` must stay installed for `envsubst`.

## To verify once the image exists

- The startup log lines match the original's.
- `default.conf` contains `listen  [::]:80;` after the first start.
