#!/usr/bin/env bash
set -euo pipefail
export LC_ALL=C DEBIAN_FRONTEND=noninteractive

phase="${1:?choose runtime or build}"
if [[ "$(dpkg --print-architecture)" != arm64 || "$(uname -m)" != aarch64 ]]; then
    echo "Native ARM64 package environment is required" >&2
    exit 2
fi
case "$phase" in
    runtime)
        packages=(ca-certificates libgomp1 libgfortran5 libstdc++6 libgcc-s1 mpich python3)
        ;;
    build)
        packages=(bzip2 cmake curl g++-15 gcc-15 gfortran-15 git libeigen3-dev libmpich-dev make ninja-build pkgconf xz-utils)
        ;;
    *) exit 2 ;;
esac

evidence=/opt/quanta-cp2k/evidence
mkdir -p "$evidence"
if [[ ! -s /etc/ssl/certs/ca-certificates.crt ]]; then
    cert_deb=ca-certificates_20260816ubuntu0.26.04.2_all.deb
    cert_sha=a7e3bf769aec16ba21ca39cba180d6d311dafcbae68346a05f137c5cc26c9ca6
    /usr/lib/apt/apt-helper download-file \
        "http://ports.ubuntu.com/ubuntu-ports/pool/main/c/ca-certificates/$cert_deb" \
        "/tmp/$cert_deb" "SHA256:$cert_sha"
    printf '%s  %s\n' "$cert_sha" "/tmp/$cert_deb" | sha256sum --check
    dpkg-deb --extract "/tmp/$cert_deb" /tmp/quanta-certs
    mkdir -p /etc/ssl/certs
    cat /tmp/quanta-certs/usr/share/ca-certificates/mozilla/*.crt >/etc/ssl/certs/ca-certificates.crt
    printf '%s  %s\n' "$cert_sha" "$cert_deb" >"$evidence/bootstrap-certificate.sha256"
    rm -rf /tmp/quanta-certs "/tmp/$cert_deb"
fi

cat >/etc/apt/sources.list.d/ubuntu.sources <<'EOF'
Types: deb
URIs: https://snapshot.ubuntu.com/ubuntu/20261107T000000Z/
Suites: resolute resolute-updates resolute-security
Components: main universe
Architectures: arm64
Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg
Check-Valid-Until: no
EOF
cp /etc/apt/sources.list.d/ubuntu.sources "$evidence/ubuntu.sources"
rm -f /etc/apt/apt.conf.d/docker-clean
apt-get -o Acquire::Retries=3 update
find /var/lib/apt/lists -maxdepth 1 -type f -name '*InRelease' -print0 \
    | sort -z | xargs -0 -r sha256sum >"$evidence/$phase-apt-release.sha256"
test -s "$evidence/$phase-apt-release.sha256"
apt-get --yes --no-install-recommends --download-only install "${packages[@]}"

printf 'package\tversion\tarchitecture\tsha256\tfile\n' >"$evidence/$phase-apt-debs.tsv"
shopt -s nullglob
archives=(/var/cache/apt/archives/*.deb)
(( ${#archives[@]} > 0 ))
for archive in "${archives[@]}"; do
    package="$(dpkg-deb -f "$archive" Package)"
    version="$(dpkg-deb -f "$archive" Version)"
    arch="$(dpkg-deb -f "$archive" Architecture)"
    hash="$(sha256sum "$archive")"
    hash="${hash%% *}"
    case "$arch" in arm64|all) ;; *) exit 2 ;; esac
    apt-cache show "$package=$version" | awk -v "expected=$hash" '
        $1 == "SHA256:" && $2 == expected { found = 1 }
        END { exit !found }
    '
    printf '%s\t%s\t%s\t%s\t%s\n' "$package" "$version" "$arch" "$hash" "${archive##*/}" \
        >>"$evidence/$phase-apt-debs.tsv"
done
apt-get --yes --no-download --no-install-recommends install "${packages[@]}"
dpkg-query -W -f='${binary:Package}\t${Version}\t${Architecture}\n' | sort >"$evidence/$phase-dpkg.tsv"
while IFS=$'\t' read -r package version arch hash filename; do
    [[ "$package" == package ]] && continue
    [[ "$(dpkg-query -W -f='${Version}\t${Architecture}' "$package")" == "$version"$'\t'"$arch" ]]
done <"$evidence/$phase-apt-debs.tsv"
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*.deb
