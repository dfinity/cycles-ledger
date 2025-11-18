#!/bin/bash

if test "$#" -ne 3; then
    echo "usage: download-pocket-ic.sh <version> <linux|darwin> <x86_64|arm64>"
    exit 1
fi

VERSION="$1"
PLATFORM="$2"
ARCH="$3"

DOWNLOAD_URL="https://github.com/dfinity/pocketic/releases/download/${VERSION}/pocket-ic-${ARCH}-${PLATFORM}.gz"
echo "downloading binary from ${DOWNLOAD_URL}"

wget -O pocket-ic.gz "${DOWNLOAD_URL}"
gunzip pocket-ic.gz
chmod +x pocket-ic
