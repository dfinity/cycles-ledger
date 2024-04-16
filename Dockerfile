# This is copied and adapted from https://github.com/dfinity/exchange-rate-canister/blob/458adc36f9c3f6b7232a8868528262c0c3eb52ab/Dockerfile

# Use this with
#
# docker build . -t cycles-ledger
# container_id=$(docker create cycles-ledger no-op)
# docker cp $container_id:cycles-ledger.wasm cycles-ledger.wasm
# docker rm --volumes $container_id

# This is the "builder", i.e. the base image used later to build the final
# code.
FROM ubuntu:20.04 as builder
SHELL ["bash", "-c"]

ARG rust_version=1.75.0

ENV TZ=UTC

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone && \
    apt -yq update && \
    apt -yqq install --no-install-recommends curl ca-certificates \
    build-essential pkg-config libssl-dev llvm-dev liblmdb-dev clang cmake \
    git jq

# Install Rust and Cargo in /opt
ENV RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:$PATH

RUN curl --fail https://sh.rustup.rs -sSf \
    | sh -s -- -y --default-toolchain ${rust_version}-x86_64-unknown-linux-gnu --no-modify-path && \
    rustup default ${rust_version}-x86_64-unknown-linux-gnu && \
    rustup target add wasm32-unknown-unknown

ENV PATH=/cargo/bin:$PATH

# Pre-build all cargo dependencies. Because cargo doesn't have a build option
# to build only the dependencies, we pretend that our project is a simple, empty
# `lib.rs`. Then we remove the dummy source files to make sure cargo rebuild
# everything once the actual source code is COPYed (and e.g. doesn't trip on
# timestamps being older)
COPY Cargo.lock .
COPY Cargo.toml .
COPY cycles-ledger/Cargo.toml cycles-ledger/Cargo.toml
COPY depositor/Cargo.toml depositor/Cargo.toml
COPY fake-cmc/Cargo.toml fake-cmc/Cargo.toml
RUN mkdir -p cycles-ledger/src && \
    touch cycles-ledger/src/lib.rs && \
    mkdir -p depositor/src && \
    touch depositor/src/lib.rs && \
    mkdir -p fake-cmc/src && \
    touch fake-cmc/src/lib.rs && \
    cargo build --target wasm32-unknown-unknown --release --package cycles-ledger && \
    rm -rf cycles-ledger/

# Install dfx
COPY dfx.json dfx.json

ENV PATH="/root/.local/share/dfx/bin:${PATH}"
RUN DFXVM_INIT_YES=true DFX_VERSION="$(jq -cr .dfx dfx.json)" \
    sh -c "$(curl -fsSL https://sdk.dfinity.org/install.sh)" && \
    dfx --version

# Start the second container
FROM builder AS build
SHELL ["bash", "-c"]

# Build
# ... put only git-tracked files in the build directory
COPY . /build
WORKDIR /build
# Creates the wasm without creating the canister
RUN dfx build --check cycles-ledger

RUN ls -sh /build
RUN ls -sh /build/.dfx/local/canisters/cycles-ledger/cycles-ledger.wasm.gz
RUN sha256sum /build/.dfx/local/canisters/cycles-ledger/cycles-ledger.wasm.gz

FROM scratch AS scratch
COPY --from=build /build/.dfx/local/canisters/cycles-ledger/cycles-ledger.wasm.gz /