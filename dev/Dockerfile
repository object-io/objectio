# The development container: the release builder's toolchain (Dockerfile,
# stage builder-base) plus what working in the repo needs. See dev/README.md.
ARG RUST_VERSION=1.94
FROM rust:${RUST_VERSION}-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
        autoconf automake libtool libclang-dev pkg-config cmake \
        protobuf-compiler libprotobuf-dev nasm \
        git curl ca-certificates gnupg jq less vim ripgrep rsync sudo \
        openssh-client python3 python3-venv python3-pip \
    && rm -rf /var/lib/apt/lists/*
RUN rustup component add rustfmt clippy

# docker CLI (the host's daemon, through its socket), gh
RUN install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian bookworm stable" \
        > /etc/apt/sources.list.d/docker.list \
    && curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg \
        -o /etc/apt/keyrings/githubcli.gpg \
    && echo "deb [signed-by=/etc/apt/keyrings/githubcli.gpg] https://cli.github.com/packages stable main" \
        > /etc/apt/sources.list.d/github-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends docker-ce-cli docker-buildx-plugin gh \
    && rm -rf /var/lib/apt/lists/*

# kubectl, helm, kind (the kind test), node 22 (the console)
ARG KUBECTL=v1.35.0
ARG HELM=v3.19.0
ARG KIND=v0.27.0
ARG NODE=22.20.0
RUN arch=$(dpkg --print-architecture) \
    && curl -fsSL "https://dl.k8s.io/release/${KUBECTL}/bin/linux/${arch}/kubectl" -o /usr/local/bin/kubectl \
    && curl -fsSL "https://kind.sigs.k8s.io/dl/${KIND}/kind-linux-${arch}" -o /usr/local/bin/kind \
    && chmod +x /usr/local/bin/kubectl /usr/local/bin/kind \
    && curl -fsSL "https://get.helm.sh/helm-${HELM}-linux-${arch}.tar.gz" | tar -xz -C /tmp \
    && mv /tmp/linux-${arch}/helm /usr/local/bin/helm \
    && node_arch=$([ "$arch" = amd64 ] && echo x64 || echo "$arch") \
    && curl -fsSL "https://nodejs.org/dist/v${NODE}/node-v${NODE}-linux-${node_arch}.tar.xz" \
        | tar -xJ -C /usr/local --strip-components=1

# The developer: same uid/gid as on the host, so files stay theirs; in the
# host's docker group (by gid), with passwordless sudo inside the container.
ARG USER=dev
ARG UID=1000
ARG GID=1000
ARG DOCKER_GID=999
RUN groupadd -g "${GID}" "${USER}" \
    && (getent group "${DOCKER_GID}" || groupadd -g "${DOCKER_GID}" hostdocker) \
    && useradd -m -u "${UID}" -g "${GID}" -G "$(getent group "${DOCKER_GID}" | cut -d: -f1)" -s /bin/bash "${USER}" \
    && echo "${USER} ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/dev
ENV CARGO_HOME=/cargo PATH=/cargo/bin:/usr/local/cargo/bin:$PATH
# A login shell resets PATH from /etc/profile: put the toolchain back.
RUN echo 'export PATH=/cargo/bin:/usr/local/cargo/bin:$PATH' > /etc/profile.d/rust.sh
USER ${USER}
