# Imagem base Rust 1.93.1 Alpine (Alpine/musl)
FROM rust:1.93.1-alpine

# Instala dependências do sistema: Go, gcc (build-base), make, pkgconfig, git, protoc
RUN apk add --no-cache \
    go \
    build-base \
    pkgconfig \
    git \
    ca-certificates \
    protobuf \
    protobuf-dev

# Instala o uniffi-bindgen-go com lockfile do repositorio
RUN cargo install --locked uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.4.0+v0.28.3

ENV PROTOC_INCLUDE=/usr/include
ENV CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=gcc
ENV CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=gcc
ENV RUSTFLAGS="-C target-feature=-crt-static"

WORKDIR /workspace

CMD ["sh", "-c", "make build-go-musl"]

