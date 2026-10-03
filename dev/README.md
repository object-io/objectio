# Development container

Everything the repo needs, in one container, on any Linux host with Docker:
the release builder's Rust toolchain (the version `rust-toolchain.toml`
pins), protoc, nasm and libclang (ISA-L), node 22 (the console), the docker
CLI, kubectl, helm, kind, gh and Python. Nothing to install on the host.

```bash
dev/devbox.sh up       # build the image, start the container
dev/devbox.sh shell    # a shell in it, in the current directory
dev/devbox.sh claude   # Claude Code in it, in the repo
dev/devbox.sh down     # stop it (caches stay)
```

- **Paths are the host's.** The directory holding the repos (`CODE`,
  default: this repo's parent) is mounted at the same path, so `target/`
  stays on the host disk and Claude Code's per-project sessions and memory
  are the same inside and out.
- **You, not root.** It runs as your uid/gid; files stay yours.
- **Host network.** Tests bind localhost ports, kind is reached as on the
  host, and so are VMs on the host's bridges (the chaos test).
- **The host's Docker.** Its socket is mounted: kind and image builds work
  from inside.
- **Carried over from your home, if present:** Claude Code (binary,
  settings, sessions, memory), `~/.ssh`, `~/.gitconfig`, gh's login,
  `~/.kube`.
- **Caches:** cargo's registry in `CODE/.devbox-cache`.

Incus (the chaos test's VMs) needs root on the host, so `deploy/chaos`
runs on the host, not in the container.
