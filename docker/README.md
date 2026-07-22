# Docker-managed Maddy

MaddyWeb itself is **not containerized**. In production, both the web process
and its helper run in a Python 3.14 virtual environment under the supplied
systemd units. `docker/config.toml` is the host-side MaddyWeb configuration for
the case where the Maddy server being administered is the fixed container
named `maddy`.

The helper calls a fixed Docker argv; it does not mount the Docker socket into
the web process. The web process remains the unprivileged `maddyweb` system
user, listens only on `127.0.0.1:8787`, and communicates with the helper over
`/run/maddyweb/helper.sock`.

The managed Submission listener remains inside the container at
`127.0.0.1:1587`. The helper reaches it with the fixed transport
`docker exec -i maddy /usr/bin/nc 127.0.0.1 1587`; port 1587 must never be
published to the host. Container network mode is otherwise an operator choice.

This repository never creates, recreates, upgrades, or replaces the managed
Maddy container. It creates only short-lived helpers: a networkless,
read-only-volume snapshot container during an approved backup, and disposable
integration fixtures. Matrix image references are digest-pinned in
`tests/integration/maddy-image-lock.json`; fixtures use isolated Docker volumes
and networks, publish no host ports, and never attempt public mail delivery.
