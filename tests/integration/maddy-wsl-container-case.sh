#!/usr/bin/env bash
set -Eeuo pipefail
IFS=$'\n\t'
umask 077

die() {
    printf 'WSL container matrix case failed: %s\n' "$*" >&2
    exit 1
}

[[ $# -eq 6 ]] || die "expected version, image, repository, Python, diagnostic root, and pull policy"
version=$1
image=$2
repository=$3
python_binary=$4
diagnostic_root=$5
allow_pull=$6

case "$version" in 0.8.2|0.9.0|0.9.1|0.9.2|0.9.3|0.9.4|0.9.5) ;; *) die "unsupported version" ;; esac
[[ "$image" =~ ^ghcr\.io/foxcpp/maddy@sha256:[0-9a-f]{64}$ ]] || die "image is not a locked GHCR digest"
[[ "$allow_pull" == true || "$allow_pull" == false ]] || die "invalid image pull policy"
[[ -d "$repository/src/maddyweb" ]] || die "repository path is invalid"
command -v -- "$python_binary" >/dev/null 2>&1 || die "Python command is unavailable"
command -v docker >/dev/null 2>&1 || die "Docker CLI is unavailable inside WSL"
command -v openssl >/dev/null 2>&1 || die "OpenSSL is required for the temporary certificate"

if [[ "$allow_pull" == true ]]; then
    docker pull --quiet "$image" >/dev/null
else
    docker image inspect "$image" >/dev/null 2>&1 || die "locked image is not local; rerun with explicit image-pull authorization"
fi

nonce=$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')
[[ "$nonce" =~ ^[0-9a-f]{16}$ ]] || die "failed to generate fixture nonce"
safe_version=${version//./-}
label="io.maddyweb.matrix=$nonce"
container="maddyweb-matrix-${safe_version}-${nonce}"
volume="maddyweb-matrix-${safe_version}-${nonce}"
network="maddyweb-matrix-${safe_version}-${nonce}"
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/maddyweb-container-${safe_version}.XXXXXXXX")
fixture_config="$repository/tests/integration/fixtures/maddy-matrix.conf"
openssl_config="$repository/tests/integration/fixtures/openssl.cnf"
[[ -f "$fixture_config" && ! -L "$fixture_config" ]] || die "fixed Maddy fixture config is missing"
[[ -f "$openssl_config" && ! -L "$openssl_config" ]] || die "fixed OpenSSL fixture config is missing"
container_created=false
volume_created=false
network_created=false

cleanup() {
    local status=$?
    set +e
    if (( status != 0 )); then
        mkdir -p -- "$diagnostic_root"
        if [[ "$container_created" == true ]]; then
            docker inspect "$container" > "$diagnostic_root/${version}-container.json" 2>&1
            docker logs "$container" > "$diagnostic_root/${version}-container.log" 2>&1
            docker exec "$container" /bin/maddy version > "$diagnostic_root/${version}-maddy-version.txt" 2>&1
        fi
    fi
    if [[ "$container_created" == true ]]; then docker rm --force --volumes "$container" >/dev/null 2>&1; fi
    if [[ "$volume_created" == true ]]; then docker volume rm --force "$volume" >/dev/null 2>&1; fi
    if [[ "$network_created" == true ]]; then docker network rm "$network" >/dev/null 2>&1; fi
    if [[ "$fixture_root" == "${TMPDIR:-/tmp}"/maddyweb-container-* && -d "$fixture_root" && ! -L "$fixture_root" ]]; then
        rm -rf -- "$fixture_root"
    fi
    exit "$status"
}
trap cleanup EXIT

install -d -m 0700 -- "$fixture_root/live/mx.example.invalid" "$fixture_root/spool"
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -config "$openssl_config" \
    -keyout "$fixture_root/live/mx.example.invalid/privkey.pem" \
    -out "$fixture_root/live/mx.example.invalid/fullchain.pem" >/dev/null 2>&1
chmod 0600 "$fixture_root/live/mx.example.invalid/privkey.pem" "$fixture_root/live/mx.example.invalid/fullchain.pem"
openssl x509 -in "$fixture_root/live/mx.example.invalid/fullchain.pem" -checkend 0 -noout >/dev/null

docker volume create --label "$label" "$volume" >/dev/null
volume_created=true
docker network create --internal --label "$label" "$network" >/dev/null
network_created=true
docker run --detach \
    --name "$container" \
    --label "$label" \
    --network "$network" \
    --user 0:0 \
    --workdir /data \
    --mount "type=volume,source=$volume,target=/data" \
    --mount "type=bind,source=$fixture_config,target=/data/maddy.conf,readonly" \
    --entrypoint /bin/maddy \
    "$image" -config /data/maddy.conf run >/dev/null
container_created=true

for _ in {1..30}; do
    running=$(docker inspect --format '{{.State.Running}}' "$container")
    [[ "$running" == true ]] && break
    sleep 0.2
done
[[ "$(docker inspect --format '{{.State.Running}}' "$container")" == true ]] || die "Maddy fixture did not stay running"

# Keep the adapter's fixed in-image executable contract covered in every
# release lane. DockerCertificateAdapter itself never invokes a shell.
docker exec "$container" /bin/ls -l \
    /bin/true /bin/cat /bin/stat /bin/chmod /bin/chown /bin/mv /bin/rm \
    /usr/bin/readlink /usr/bin/nc >/dev/null
docker exec "$container" /bin/mkdir -p /data/maddyweb-cert-test

PYTHONPATH="$repository/src" "$python_binary" \
    "$repository/tests/integration/wsl_container_case.py" \
    --container "$container" \
    --expected-version "$version" \
    --certificate "$fixture_root/live/mx.example.invalid/fullchain.pem" \
    --private-key "$fixture_root/live/mx.example.invalid/privkey.pem" \
    --spool-dir "$fixture_root/spool"
