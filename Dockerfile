# syntax=docker/dockerfile:1
#
# sister-sign container image (T25): image kecil berisi binary `sister-sign` saja.
#
#   build   : debian:trixie + g++-14 + CMake 3.31 + libssl-dev (OpenSSL 3.5), semua dari apt
#   runtime : debian:trixie-slim + libssl3t64 (OpenSSL 3.5), user non-root, tanpa kunci
#
# Pakai:
#   docker build -t sister-sign .
#   docker run --rm --network none sister-sign -version
#
# Base image dipin by digest (index multi-arch). Untuk update: `docker pull <tag>` lalu salin
# digest dari `docker image inspect --format '{{index .RepoDigests 0}}' <tag>`.
ARG BUILD_IMAGE=debian:trixie@sha256:9c6e381421d0f48d1b8133e573f33c185ee16cbf505eda9c4a8a4791b25ea8a6
ARG RUNTIME_IMAGE=debian:trixie-slim@sha256:a72b4433de1cf7d6bae0c4cee74d0547f58601a643b3375f070c51600d63b6b2

# ---------------------------------------------------------------------------------------------
FROM ${BUILD_IMAGE} AS build

# git + ca-certificates untuk FetchContent (glaze, doctest).
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      g++-14 cmake ninja-build git ca-certificates libssl-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# Hanya yang dibutuhkan untuk configure + build (lihat juga .dockerignore).
COPY CMakeLists.txt ./
COPY include/ include/
COPY src/ src/
COPY tests/ tests/
COPY bench/ bench/

# OpenSSL >= 3.5 diwajibkan oleh find_package di CMakeLists.txt.
# -Werror OFF di sini: gerbang warning ada di CI; warning optimizer (Release) tidak boleh
# memblokir build image rilis.
RUN cmake -S . -B /build -G Ninja \
      -DCMAKE_CXX_COMPILER=g++-14 \
      -DCMAKE_BUILD_TYPE=Release \
      -DSISTER_SIGN_WERROR=OFF \
 && cmake --build /build --target sister-sign \
 && install -D -m 0755 -s /build/sister-sign /out/sister-sign \
 && ldd /out/sister-sign \
 && /out/sister-sign -version

# ---------------------------------------------------------------------------------------------
FROM ${RUNTIME_IMAGE} AS runtime

# Build dan runtime sama-sama trixie: libstdc++6 (GCC 14) dan libssl3t64 (OpenSSL 3.5) cocok.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      libssl3t64 libstdc++6 \
 && rm -rf /var/lib/apt/lists/* \
 && ssl="$(dpkg-query -W -f='${Version}' libssl3t64)" \
 && echo "libssl3t64 ${ssl}" \
 && dpkg --compare-versions "${ssl}" ge 3.5 \
 && useradd --system --uid 10001 --user-group --no-create-home \
      --home-dir /nonexistent --shell /usr/sbin/nologin sister

COPY --from=build /out/sister-sign /usr/local/bin/sister-sign

LABEL org.opencontainers.image.title="sister-sign" \
      org.opencontainers.image.description="Sign and verify software artifacts (Ed25519, ECDSA P-256, RSA-PSS 3072)" \
      org.opencontainers.image.source="https://github.com/filbertengyo/sisters-sign"

USER 10001:10001
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/sister-sign"]
CMD ["-help"]
