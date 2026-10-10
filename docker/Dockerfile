# syntax=docker/dockerfile:1
#
# aria2 container delivery: multi-stage Alpine build, dynamic runtime.
#
#   docker build -f docker/Dockerfile -t fs088/aria2:latest-own .
#
# Design (see AGENTS.md "Container Delivery"):
#   * staged build, based on alpine:latest
#   * compiled with clang/clang++ (never gcc/g++)
#   * all features enabled, OpenSSL preferred for TLS/crypto
#   * runtime image carries only the shared libraries aria2c links against
#   * options come from a baked config file + CLI args, NOT env vars
#   * everything is present in the image; nothing is fetched at runtime

###############################################################################
# Stage 1 - build
###############################################################################
FROM alpine:latest AS build

# Build-time toolchain + headers. clang is used explicitly below; gcc is only
# present (via build-base) to provide the C++ standard library / libgcc that
# clang++ links against.
RUN apk add --no-cache \
        build-base \
        clang \
        llvm \
        autoconf \
        automake \
        libtool \
        m4 \
        pkgconf \
        gettext \
        gettext-dev \
        ca-certificates \
        openssl-dev \
        libxml2-dev \
        sqlite-dev \
        c-ares-dev \
        zlib-dev \
        libssh2-dev \
        libuv-dev

WORKDIR /src
COPY . /src

# --with-openssl / --without-gnutls forces OpenSSL (project preference).
# OpenSSL also replaces libgcrypt/libnettle for BT + digest + WebSocket.
# NLS is disabled so no locale data ships in the image.
RUN autoreconf -fi \
    && ./configure \
        CC=clang \
        CXX=clang++ \
        --prefix=/usr \
        --sysconfdir=/etc \
        --disable-nls \
        --with-openssl \
        --without-gnutls \
        --without-libgcrypt \
        --without-libnettle \
        --without-libgmp \
        --with-libxml2 \
        --without-libexpat \
        --with-sqlite3 \
        --with-libz \
        --with-libcares \
        --with-libssh2 \
        --with-libuv \
        --enable-epoll \
        --enable-websocket \
        CFLAGS="-O2 -pipe" \
        CXXFLAGS="-O2 -pipe" \
    && make -j"$(nproc)" \
    && make -j"$(nproc)" install DESTDIR=/install \
    && strip /install/usr/bin/aria2c

###############################################################################
# Stage 2 - runtime
###############################################################################
FROM alpine:latest AS runtime

# Only the shared libraries aria2c links against, plus CA certificates.
RUN apk add --no-cache \
        ca-certificates \
        libssl3 \
        libcrypto3 \
        libstdc++ \
        libgcc \
        zlib \
        c-ares \
        libssh2 \
        libxml2 \
        sqlite-libs \
        libuv \
    && addgroup -g 1000 -S aria2 \
    && adduser -u 1000 -S aria2 -G aria2 \
    && mkdir -p /config /downloads \
    && chown -R aria2:aria2 /config /downloads

COPY --from=build --chown=root:root /install/ /
COPY --chown=aria2:aria2 docker/conf/aria2.conf /config/aria2.conf
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh

# Normalize line endings (defensive against CRLF) and make the bootstrap executable.
RUN sed -i 's/\r$//' /usr/local/bin/entrypoint.sh \
    && chmod 0755 /usr/local/bin/entrypoint.sh

USER aria2
WORKDIR /downloads

# RPC port + BitTorrent/DHT listen port (TCP + UDP), matching aria2.conf.
EXPOSE 6800 51413 51413/udp

# entrypoint.sh only ensures the session file exists, then execs aria2c; it
# reads no environment variables. --conf-path is fixed inside it so it survives
# argument overrides; extra flags passed to `docker run` are appended and win.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["--log-level=info"]
