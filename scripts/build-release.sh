#!/usr/bin/env bash
# Build the i2per prod release tarball + MANIFEST.
#
# Run from the repo root: `just release` (or `bash scripts/build-release.sh`).
#
# Output (git-ignored `dist/`):
#   dist/i2per-<vsn>-<source_rev>.tar.gz
#   dist/i2per-<vsn>-<source_rev>.tar.gz.manifest
#
# The MANIFEST records the complete provenance and sha256 of the artifact, so a
# deployment can confirm exactly which tarball it is running before it upgrades.
# A normal release refuses a dirty JJ working copy; diagnostic builds must
# opt out with I2PER_ALLOW_DIRTY_RELEASE=1 and are not publication artifacts.
#
# Two environments, one build:
#   1. System Erlang (non-nix) on the PATH — build right here.
#   2. nix-built Erlang (the devenv dev box): the ERTS and crypto/ssl NIFs
#      link against /nix/store glibc, so an include_erts tarball made from
#      them CANNOT boot on the Debian container (the nix dynamic loader path
#      does not exist there). In that case the build runs inside a throwaway
#      Debian 13 container (podman/docker) — the same distro the tarball will
#      run on, so ERTS + NIF ABI match by construction.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
DIST_DIR="$ROOT/dist"
APP_SRC="$ROOT/apps/i2per/src/i2per.app.src"

CONTAINER_IMAGE="${I2PER_BUILD_IMAGE:-debian:13-slim}"
REBAR3_ESCRIPT_URL="${I2PER_REBAR3_URL:-https://github.com/erlang/rebar3/releases/download/3.26.0/rebar3}"
DEBIAN_BUILD_DIR="/src/_build-debian"
DEBIAN_APP_PKGS="erlang-nox erlang-dev git"

git_safe() {
    git -c safe.directory="$ROOT" "$@"
}

source_tree_digest() {
    local listing digest path
    listing="$(mktemp)"
    if ! git_safe ls-files -z >"$listing"; then
        rm -f "$listing"
        echo "error: could not enumerate tracked source files" >&2
        return 1
    fi
    digest="$(
        {
            while IFS= read -r -d '' path; do
                if [ -L "$path" ]; then
                    printf 'symlink %s -> %s\n' "$path" "$(readlink "$path")"
                elif [ -f "$path" ]; then
                    sha256sum "$path"
                else
                    printf 'missing %s\n' "$path"
                fi
            done <"$listing"
        } | sha256sum | cut -d' ' -f1
    )"
    rm -f "$listing"
    [ -n "$digest" ] || return 1
    printf '%s\n' "$digest"
}

source_dirty() {
    local status
    # `jj` may be installed while the checkout is git-only -- the devenv shell
    # has it either way. So the branch is taken on `jj root` succeeding, not
    # on the binary being findable, or a git repo dies with "no jj repo".
    if command -v jj >/dev/null 2>&1 && jj root >/dev/null 2>&1; then
        if ! status="$(jj status --no-pager)"; then
            echo "error: could not inspect the jj working copy" >&2
            return 2
        fi
        printf '%s\n' "$status" | grep '^Working copy changes:' >/dev/null
    elif command -v git >/dev/null 2>&1; then
        if ! status="$(git_safe status --porcelain)"; then
            echo "error: could not inspect the git working copy" >&2
            return 2
        fi
        [ -n "$status" ]
    else
        echo "error: release builds require jj or git" >&2
        return 2
    fi
}

source_commit_id() {
    local commit rev jj_state
    if command -v jj >/dev/null 2>&1 && jj root >/dev/null 2>&1; then
        jj_state="$(jj log -r @ --no-graph --no-pager -T 'if(empty, "empty", "nonempty")')" || return 1
        case "$jj_state" in
            empty) rev=@- ;;
            nonempty) rev=@ ;;
            *) return 1 ;;
        esac
        commit="$(jj log -r "$rev" --no-graph --no-pager -T 'commit_id')" || return 1
    elif command -v git >/dev/null 2>&1; then
        commit="$(git_safe rev-parse HEAD)" || return 1
    else
        return 1
    fi
    commit="${commit//[[:space:]]/}"
    [ -n "$commit" ] || return 1
    printf '%s\n' "$commit"
}

core_build() {
    # Assumes rebar3 + erl on PATH. base_dir is the REBAR_BASE_DIR.
    local base_dir="${1:?core_build needs a base dir}"
    for bin in rebar3 erl sha256sum tar git; do
        command -v "$bin" >/dev/null 2>&1 || {
            echo "error: '$bin' not on PATH" >&2
            exit 1
        }
    done

    local vsn relx_vsn rev source_commit source_digest otp_vsn
    vsn="$(sed -n 's/^[[:space:]]*{vsn, "\([^"]*\)"}.*/\1/p' "$APP_SRC" | head -1)"
    [ -n "$vsn" ] || { echo "error: could not read {vsn, ...} from $APP_SRC" >&2; exit 1; }

    # release vsn is baked into rebar.config too — assert they can't drift.
    relx_vsn="$(sed -n 's/^[[:space:]]*{release, {i2per, "\([^"]*\)"}.*/\1/p' "$ROOT/rebar.config" | head -1)"
    if [ -n "$relx_vsn" ] && [ "$relx_vsn" != "$vsn" ]; then
        echo "error: relx release vsn '$relx_vsn' != app vsn '$vsn' — keep rebar.config and i2per.app.src in sync" >&2
        exit 1
    fi

    if [ "${I2PER_ALLOW_DIRTY_RELEASE:-0}" != "1" ] \
        && [ "${I2PER_SOURCE_VERIFIED:-0}" != "1" ] \
        && source_dirty; then
        echo "error: release builds require a clean jj/git working copy" >&2
        echo "       commit/stash the source first, or set I2PER_ALLOW_DIRTY_RELEASE=1 for a diagnostic build" >&2
        exit 1
    fi

    source_commit="${I2PER_SOURCE_COMMIT:-}"
    if [ -z "$source_commit" ]; then
        if ! source_commit="$(source_commit_id)"; then
            echo "error: could not determine the source commit" >&2
            exit 1
        fi
    fi
    if ! printf '%s\n' "$source_commit" | grep -Eq '^[0-9a-f]{40,64}$'; then
        echo "error: source commit must be a 40-64 character lowercase hex id" >&2
        exit 1
    fi
    source_digest="${I2PER_SOURCE_TREE_SHA256:-}"
    if [ -z "$source_digest" ]; then
        source_digest="$(source_tree_digest)"
    fi
    if ! printf '%s\n' "$source_digest" | grep -Eq '^[0-9a-f]{64}$'; then
        echo "error: source tree digest must be a SHA-256 hex value" >&2
        exit 1
    fi
    rev="${I2PER_SOURCE_REV:-${source_commit:0:12}}"
    if ! printf '%s\n' "$rev" | grep -Eq '^[0-9a-f]{7,64}$'; then
        echo "error: source revision must be a 7-64 character lowercase hex id" >&2
        exit 1
    fi
    otp_vsn="$(erl -noshell -eval 'io:format("~s", [erlang:system_info(otp_release)]), halt().')"

    echo "== rebar3 as prod tar (vsn $vsn, otp $otp_vsn, base $base_dir) =="
    REBAR_BASE_DIR="$base_dir" rebar3 as prod tar

    local rel_tgz="$base_dir/prod/rel/i2per/i2per-$vsn.tar.gz"
    [ -f "$rel_tgz" ] || { echo "error: expected relx output at $rel_tgz" >&2; exit 1; }

    if [ "${I2PER_DEBIAN_BUILD:-0}" = "1" ]; then
        # Self-containment gate inside the container: every ELF in the tarball
        # must resolve on Debian (this catches nix-store linkage at build time,
        # where it is cheap to fix, instead of on the target machine).
        echo "== self-containment gate (in-container) =="
        local smoke_dir
        smoke_dir="$(mktemp -d /tmp/i2per-smoke.XXXXXX)"
        tar -xzf "$rel_tgz" -C "$smoke_dir"
        local beam
        beam="$(find "$smoke_dir/erts-"* -maxdepth 1 -name beam.smp | head -1)"
        if readelf -l "$beam" 2>/dev/null | grep -q '/nix/store' \
            || (command -v file >/dev/null && file "$beam" | grep -q '/nix/store'); then
            echo "error: container-built ERTS is still nix-linked — check the build image" >&2
            exit 1
        fi
        local so
        while IFS= read -r -d '' so; do
            if ldd "$so" 2>/dev/null | grep -q 'not found'; then
                echo "error: $so has unresolved symbols in the Debian build image" >&2
                exit 1
            fi
        done < <(find "$smoke_dir" -name '*.so' -print0 | sort -z)
        echo "  ERTS + all NIFs resolve on Debian"
        rm -rf "$smoke_dir"
    fi

    mkdir -p "$DIST_DIR"
    local artifact="$DIST_DIR/i2per-$vsn-$rev.tar.gz"
    cp "$rel_tgz" "$artifact"
    check_release_profile "$artifact" "$vsn"
    local sha
    sha="$(sha256sum "$artifact" | cut -d' ' -f1)"
    {
        echo "# $artifact"
        echo "artifact: $(basename "$artifact")"
        echo "vsn: $vsn"
        echo "source_rev: $rev"
        echo "source_commit: $source_commit"
        echo "source_tree_sha256: $source_digest"
        echo "otp_vsn: $otp_vsn"
        echo "build_date: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "sha256: $sha"
    } > "$artifact.manifest"

    echo "== built =="
    echo "artifact: $artifact"
    echo "sha256:   $sha"
    echo "== manifest =="
    cat "$artifact.manifest"
}

## The posture, not the mechanism: the default install must not accept incoming
## distribution connections. How that is achieved is a deployment concern — the
## deployment repository ships its own vm.args and its own provisioning — so
## this states the posture, says which mechanism it found, and fails only on a
## configuration that would genuinely expose a default install.
##
## The three cases, and why they differ:
##
##   - an explicit `-dist_listen false`: the posture is met, by the shipped
##     default. Reported and passed. Note that this is also what makes the node
##     hidden (see erl(1)), so the shipped default is closed on both counts.
##   - an explicit `-dist_listen true`: a default install that listens. Failed.
##   - no flag at all: erl(1) says "by default a node will listen for incoming
##     connections", so this is the *unsafe* reading — but it is exactly the
##     shape a deployment that layers its own arguments produces, so it is
##     reported loudly and not failed. Failing a build here would be this
##     repository re-asserting, in the release check, a policy that #W1NX4KP
##     moved to the deployment repository.
check_distribution_posture() {
    local vm_args="$1"
    printf '%s\n' "$vm_args" | grep -- '-dist_listen false' >/dev/null && {
        echo "  distribution posture: default install does not listen (explicit -dist_listen false)"
        return 0
    }
    if printf '%s\n' "$vm_args" | grep -- '-dist_listen true' >/dev/null; then
        echo "error: release explicitly enables the distribution listener" >&2
        exit 1
    fi
    echo "  warning: no -dist_listen flag in the shipped vm.args." >&2
    echo "  warning: erl(1) defaults a node to listening for incoming distribution" >&2
    echo "  warning: connections. A default install would therefore be reachable." >&2
    echo "  warning: Supply -dist_listen false unless distribution is intended." >&2
}

check_release_profile() {
    local artifact="$1"
    local vsn="$2"
    local sys_config vm_args
    sys_config="$(tar -xOf "$artifact" "releases/$vsn/sys.config")"
    vm_args="$(tar -xOf "$artifact" "releases/$vsn/vm.args")"
    if printf '%s\n' "$vm_args" | grep -- '-setcookie i2per-dev-cookie-change-me' >/dev/null; then
        echo "error: release contains the predictable development cookie" >&2
        exit 1
    fi
    check_distribution_posture "$vm_args"
    if printf '%s\n' "$vm_args" | grep -E '^[[:space:]]*-setcookie([[:space:]]|$)' >/dev/null; then
        echo "error: fallback release unexpectedly ships a distribution cookie" >&2
        exit 1
    fi
    if ! printf '%s\n' "$vm_args" | grep -- '-start_epmd false' >/dev/null; then
        echo "error: release does not explicitly disable epmd" >&2
        exit 1
    fi
    if ! printf '%s\n' "$sys_config" | grep 'ntcp2_published, false' >/dev/null; then
        echo "error: release does not carry ntcp2_published=false" >&2
        exit 1
    fi
    if ! printf '%s\n' "$sys_config" | grep 'live_network, false' >/dev/null; then
        echo "error: release does not carry live_network=false" >&2
        exit 1
    fi
    if ! printf '%s\n' "$sys_config" | grep 'data_dir, "./data"' >/dev/null; then
        echo "error: release does not carry a user-writable standalone data_dir" >&2
        exit 1
    fi
    if printf '%s\n' "$sys_config" | grep 'reseed, #{enabled => true' >/dev/null; then
        echo "error: release unexpectedly enables live reseeding" >&2
        exit 1
    fi
    for required_doc in LICENSE NOTICE README.md \
        docs/documentation.md docs/protocol.md; do
        if ! tar -tzf "$artifact" | grep -Fx "$required_doc" >/dev/null; then
            echo "error: release is missing $required_doc" >&2
            exit 1
        fi
    done
    echo "  safe-default profile and license-document checks passed"
}

erl_uses_nix_erts() {
    local root beam
    root="$(erl -noshell -eval 'io:format("~s", [code:root_dir()]), halt().')"
    beam="$(find "$root"/erts-*/bin -maxdepth 1 -name beam.smp 2>/dev/null | head -1)"
    [ -f "$beam" ] || return 1
    if command -v readelf >/dev/null 2>&1; then
        readelf -l "$beam" 2>/dev/null | grep -q '/nix/store'
    else
        file "$beam" 2>/dev/null | grep -q '/nix/store'
    fi
}

build_in_container() {
    local runtime="" c
    for c in podman docker; do
        if command -v "$c" >/dev/null 2>&1; then runtime="$c"; break; fi
    done
    if [ -z "$runtime" ]; then
        cat >&2 <<'EOF'
error: the local Erlang is nix-built (ERTS links against /nix/store glibc), so
       an include_erts tarball from it cannot boot on the Debian container.
       Release builds must run inside a Debian 13 container — but neither
       podman nor docker is installed. Install podman, or build the release on
       the Debian 13 machine that will run it (set I2PER_DEBIAN_BUILD=1 and
       run scripts/build-release.sh there).
EOF
        exit 1
    fi

    if [ "${I2PER_ALLOW_DIRTY_RELEASE:-0}" != "1" ] && source_dirty; then
        echo "error: release builds require a clean jj/git working copy" >&2
        exit 1
    fi

    local rev source_commit source_digest
    source_commit="${I2PER_SOURCE_COMMIT:-}"
    if [ -z "$source_commit" ]; then
        if ! source_commit="$(source_commit_id)"; then
            echo "error: could not determine the source commit" >&2
            exit 1
        fi
    fi
    if ! printf '%s\n' "$source_commit" | grep -Eq '^[0-9a-f]{40,64}$'; then
        echo "error: source commit must be a 40-64 character lowercase hex id" >&2
        exit 1
    fi
    source_digest="${I2PER_SOURCE_TREE_SHA256:-}"
    if [ -z "$source_digest" ]; then
        source_digest="$(source_tree_digest)"
    fi
    if ! printf '%s\n' "$source_digest" | grep -Eq '^[0-9a-f]{64}$'; then
        echo "error: source tree digest must be a SHA-256 hex value" >&2
        exit 1
    fi
    rev="${I2PER_SOURCE_REV:-${source_commit:0:12}}"
    if ! printf '%s\n' "$rev" | grep -Eq '^[0-9a-f]{7,64}$'; then
        echo "error: source revision must be a 7-64 character lowercase hex id" >&2
        exit 1
    fi

    echo "== local ERTS is nix-linked — building inside $CONTAINER_IMAGE via $runtime =="
    # The single-quoted program must expand only inside the container.
    # shellcheck disable=SC2016
    "$runtime" run --rm \
        --env I2PER_ALLOW_DIRTY_RELEASE="${I2PER_ALLOW_DIRTY_RELEASE:-0}" \
        --env I2PER_REBAR3_URL="$REBAR3_ESCRIPT_URL" \
        --env DEBIAN_APP_PKGS="$DEBIAN_APP_PKGS" \
        --env I2PER_SOURCE_REV="$rev" \
        --env I2PER_SOURCE_COMMIT="$source_commit" \
        --env I2PER_SOURCE_TREE_SHA256="$source_digest" \
        --env I2PER_SOURCE_VERIFIED=1 \
        --env I2PER_DEBIAN_BUILD=1 \
        -v "$ROOT:/src:rw" \
        "$CONTAINER_IMAGE" \
        bash -euo pipefail -c '
        export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq >/dev/null
        apt-get install -y -qq --no-install-recommends ca-certificates curl $DEBIAN_APP_PKGS >/dev/null
        curl -fsSL -o /usr/local/bin/rebar3 "$I2PER_REBAR3_URL"
        chmod +x /usr/local/bin/rebar3
        cd /src
        rm -rf '"$DEBIAN_BUILD_DIR"'
        bash scripts/build-release.sh
        rm -rf '"$DEBIAN_BUILD_DIR"'
    '
}

if [ "${I2PER_DEBIAN_BUILD:-0}" = "1" ]; then
    # inside the Debian build container — nothing nix here, build directly
    core_build "/src/_build-debian"
elif erl_uses_nix_erts; then
    build_in_container
else
    core_build "$ROOT/_build"
fi