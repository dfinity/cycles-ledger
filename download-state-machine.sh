#!/bin/bash

if test "$#" -ne 2; then
    echo "usage: download-state-machine.sh <ic release hash> <linux|darwin>"
    exit 1
fi

IC_RELEASE_HASH="$1"
PLATFORM="$2"

DOWNLOAD_URL="https://download.dfinity.systems/ic/${IC_RELEASE_HASH}/binaries/x86_64-${PLATFORM}/ic-test-state-machine.gz"
echo "downloading binary from ${DOWNLOAD_URL}"

wget "${DOWNLOAD_URL}"
gunzip ic-test-state-machine.gz
chmod +x ic-test-state-machine