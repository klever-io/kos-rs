# Imagem base Rust 1.93.1 slim (Debian/glibc)
FROM rust:1.93.1-slim

# Instala dependências do sistema: Go, gcc, make, pkg-config, git
RUN apt-get update && apt-get install -y --no-install-recommends \
    golang-go \
    build-essential \
    pkg-config \
    git \
    ca-certificates \
    protobuf-compiler \
    libprotobuf-dev \
    && rm -rf /var/lib/apt/lists/*

# Instala o uniffi-bindgen-go com lockfile do repositorio
RUN cargo install --locked uniffi-bindgen-go --git https://github.com/NordSecurity/uniffi-bindgen-go --tag v0.7.1+v0.31.0

ENV PROTOC_INCLUDE=/usr/include

WORKDIR /workspace

CMD ["bash", "-c", "make build-go"]
