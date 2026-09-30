# Runs objectio-transport-te's Transfer Engine tests (TCP mode: no RDMA
# hardware needed). From the repository root:
#
#   docker build -f crates/objectio-transport-te/test.Dockerfile -t te-test .
#   docker run --rm te-test
#
# Mooncake is pinned to the commit the bindings in vendor/ were copied from.
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y git curl ca-certificates sudo pkg-config libclang-dev clang
ARG MOONCAKE_REF=c3fa13ecaf1038df933dcb784ff8ffe026381100
RUN git clone https://github.com/kvcache-ai/Mooncake /mooncake && cd /mooncake \
 && git checkout ${MOONCAKE_REF} && git submodule update --init --recursive
WORKDIR /mooncake
RUN bash dependencies.sh -y
# Transfer Engine only: no store, etcd, CUDA, tests or benchmarks.
RUN cmake -S . -B build -DWITH_TE=ON -DWITH_STORE=OFF -DWITH_STORE_RUST=OFF \
      -DWITH_P2P_STORE=OFF -DBUILD_UNIT_TESTS=OFF -DBUILD_BENCHMARK=OFF \
      -DUSE_ETCD=OFF -DUSE_CUDA=OFF -DWITH_RUST_EXAMPLE=OFF \
 && cmake --build build -j"$(nproc)"
RUN curl -sSf https://sh.rustup.rs | sh -s -- -y --profile minimal --default-toolchain none
ENV PATH=/root/.cargo/bin:$PATH \
    MOONCAKE_BUILD_DIR=/mooncake/build \
    MOONCAKE_TE_INCLUDE_DIR=/mooncake/mooncake-transfer-engine/include \
    LD_LIBRARY_PATH=/mooncake/build/mooncake-common
COPY . /src
WORKDIR /src
# rust-toolchain.toml pins the compiler; building here caches it in the image.
RUN cargo test -p objectio-transport-te --features te --no-run
CMD ["cargo", "test", "-p", "objectio-transport-te", "--features", "te"]
