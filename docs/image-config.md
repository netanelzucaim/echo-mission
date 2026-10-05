# Image configuration: what matches the original

Back to the [README](../README.md). Checked by `make test` and `make fsdiff`.

The assignment requires the filesystem layout, user, working directory, ports and
entrypoint to match the original exactly. The `Containerfile` copies those, and also
the settings the assignment does not name, so the image behaves as a drop-in replacement.
All values were taken from `scans/baseline/image/inspect.json` and
`scans/baseline/image/history.txt`.

| Setting | Original | This image |
|---|---|---|
| User | root, with `nginx` user/group (UID/GID 101) for workers | Same |
| Working directory | Not set | Same |
| Exposed port | 80/tcp | Same |
| Entrypoint | `/docker-entrypoint.sh` | Same (script extracted unchanged, in `rootfs/`) |
| Startup scripts | Four files in `/docker-entrypoint.d/` | Same (extracted unchanged) |
| Command | `nginx -g "daemon off;"` | Same |
| Stop signal | `SIGQUIT` (graceful shutdown) | Same |
| Environment | `NGINX_VERSION`, `NJS_VERSION`, `NJS_RELEASE`, `PKG_RELEASE` | Same |
| Label `maintainer` | `NGINX Docker Maintainers <docker-maint@nginx.com>` | **Changed**, see below |

## Deliberate differences

- **`maintainer` label.** Set to `Netanel Zucaim <netanelzucaim100@gmail.com>`.
  This image is rebuilt and patched by me, not by the NGINX maintainers, so keeping
  their name on it would misstate who is responsible for it. The label is metadata
  only and nothing functional depends on it.
- **Base-evolution differences.** The image is rebuilt on a current `debian:bookworm-slim`
  (plus `apt-get upgrade`), so a few base-provided files differ from the original's
  May-2024 base: the `debian-archive-*` keyrings (buster-era → trixie-era) and a `tzdata`
  entry or two. These come from Debian moving forward, not from anything this project
  changed, and are the expected, desirable result of patching via a fresh base.

A full filesystem diff against the original shows no other differences: every file under
the nginx paths, the `nginx -V` flags, the Docker config (entrypoint, cmd, ports, env,
stop signal, user), the conffiles, the four modules with their debug twins, and the njs
CLI (`/usr/bin/njs`) all match, and so do the version strings of all five nginx packages
(`dpkg-query`).

**nginx.org's apt signing key** (`/etc/apt/keyrings/nginx-archive-keyring.gpg`). The
original has it because its build installed nginx from nginx.org's repository. Nothing
in this image uses it, since nginx is built from source, but the `Containerfile` fetches
it with the same commands as the original's build (`scans/baseline/image/history.txt`:
`gpg1 --recv-keys` from the keyservers, then `gpg1 --export`), so the file is there with
the same path and mode. Its bytes differ (8480 vs 6543): it is the same key (fingerprint
`573BFD6B…7BD9BF62`), but the keyserver now carries nginx's renewed self-signature, which
moves the expiry from 2024-06-14 to 2027-05-24. That is what the original's build would
produce today. The fetch needs a keyserver reachable at build time.
