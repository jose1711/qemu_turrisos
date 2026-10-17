#!/bin/bash
# download OpenWrt kernel and Turris OS medkit, verify them
# and extract the medkit into root/
#
# usage: ./fetch.sh [--no-verify] [VERSION]
#   VERSION      Turris OS version as listed in https://repo.turris.cz/archive/
#                (e.g. 3.11.23, 5.0.3), the latest release when omitted
#   --no-verify  skip checksum and signature verification

LANG=C
TURRIS_REPO=https://repo.turris.cz
KERNEL_URL=https://downloads.openwrt.org/snapshots/targets/armsr/armv7
KERNEL_FILE=openwrt-armsr-armv7-generic-kernel.bin

usage() {
  sed -n '5,9s/^# \{0,1\}//p' "$0"
  exit 1
}

verify=1
version=latest
while [ $# -gt 0 ]
do
  case "$1" in
    --no-verify) verify=0 ;;
    -*) usage ;;
    *) version=$1 ;;
  esac
  shift
done

if ! [[ $version =~ ^(latest|[0-9][0-9a-z.-]*)$ ]]
then
  echo "Invalid version: $version"
  exit 1
fi

cd "$(dirname "$0")"

if [ -e root ]
then
  echo "root/ already exists, remove it first (sudo rm -rf root)"
  exit 1
fi

missing=""
for cmd in wget tar sha256sum
do
  command -v $cmd >/dev/null || missing="$missing $cmd"
done
if [ -n "$missing" ]
then
  echo "Missing commands:$missing"
  exit 1
fi

# signify, signify-openbsd and usign share the same command line,
# python fallback is used when none of them is installed
signify=""
if [ $verify -eq 1 ]
then
  for cmd in signify signify-openbsd usign
  do
    if command -v $cmd >/dev/null
    then
      signify=$cmd
      break
    fi
  done
  if [ -z "$signify" ] && ! python3 -c 'import cryptography' 2>/dev/null
  then
    echo "Can't verify signatures, install signify (or python3 cryptography module) or use --no-verify"
    exit 1
  fi
fi

verify_signature() {
  # $1 = public key, $2 = signature, $3 = signed file
  if [ -n "$signify" ]
  then
    $signify -V -p "$1" -x "$2" -m "$3"
  else
    python3 verify_signify.py "$1" "$2" "$3"
  fi
}

download() {
  wget -q --show-progress -O "$2" "$1"
}

# medkit location differs between releases
case "$version" in
  latest) candidates="$TURRIS_REPO/hbs/medkit/medkit-omnia-latest.tar.gz" ;;
  3.*) candidates="$TURRIS_REPO/archive/omnia/$version/medkit/omnia-medkit-latest.tar.gz
                   $TURRIS_REPO/archive/omnia/$version/omnia-medkit-latest.tar.gz" ;;
  *) candidates="$TURRIS_REPO/archive/$version/medkit/omnia-medkit-latest.tar.gz" ;;
esac
url=""
for candidate in $candidates
do
  if wget -q --spider "$candidate"
  then
    url=$candidate
    break
  fi
done
if [ -z "$url" ]
then
  echo "Turris OS $version not found, see $TURRIS_REPO/archive/"
  exit 1
fi

# old releases are not signed
if [ $verify -eq 1 ] && ! wget -q --spider "$url.sig"
then
  echo "No signature available for $url, use --no-verify to skip verification"
  exit 1
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

echo "Downloading kernel.."
download "$KERNEL_URL/$KERNEL_FILE" "$tmp/$KERNEL_FILE" || exit 1
if [ $verify -eq 1 ]
then
  echo "Verifying kernel.."
  download "$KERNEL_URL/sha256sums" "$tmp/sha256sums" || exit 1
  download "$KERNEL_URL/sha256sums.sig" "$tmp/sha256sums.sig" || exit 1
  verify_signature keys/openwrt-snapshot.pub "$tmp/sha256sums.sig" "$tmp/sha256sums" || exit 1
  grep " \*$KERNEL_FILE\$" "$tmp/sha256sums" > "$tmp/kernel.sha256" || exit 1
  (cd "$tmp" && sha256sum -c kernel.sha256) || exit 1
fi

echo "Downloading Turris OS $version.."
download "$url" "$tmp/medkit.tar.gz" || exit 1
if [ $verify -eq 1 ]
then
  echo "Verifying Turris OS $version.."
  download "$url.sig" "$tmp/medkit.tar.gz.sig" || exit 1
  verify_signature keys/turris-release.pub "$tmp/medkit.tar.gz.sig" "$tmp/medkit.tar.gz" || exit 1
  if wget -q --spider "$url.sha256"
  then
    download "$url.sha256" "$tmp/medkit.tar.gz.sha256" || exit 1
    echo "$(cut -d' ' -f1 "$tmp/medkit.tar.gz.sha256")  medkit.tar.gz" > "$tmp/medkit.sha256"
    (cd "$tmp" && sha256sum -c medkit.sha256) || exit 1
  fi
fi

mv "$tmp/$KERNEL_FILE" zImage || exit 1

# extract as root to keep file ownership
echo "Extracting Turris OS $version into root/.."
sudo=""
[ "$(id -u)" -ne 0 ] && sudo=sudo
mkdir root || exit 1
if ! $sudo tar xzf "$tmp/medkit.tar.gz" -C root
then
  echo "Extraction failed, remove root/ before trying again (sudo rm -rf root)"
  exit 1
fi

echo "Done, start it with: sudo ./start_omnia.sh"
