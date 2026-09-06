# joinedcontext-platform: one image, two binaries (context-gateway = entrypoint, jcctl = `docker run … jcctl`).
# Published by .github/workflows/image.yml as ghcr.io/marek-mraz/joinedcontext-platform, pinned by digest in the deployment.
FROM rust:1.90-slim-bookworm AS build
WORKDIR /src
RUN apt-get update && apt-get install -y --no-install-recommends pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
# dependency layer first so source edits do not rebuild the world
COPY Cargo.toml Cargo.lock ./
COPY crates/jc-core/Cargo.toml crates/jc-core/Cargo.toml
COPY crates/context-gateway/Cargo.toml crates/context-gateway/Cargo.toml
COPY crates/jcctl/Cargo.toml crates/jcctl/Cargo.toml
RUN mkdir -p crates/jc-core/src crates/context-gateway/src crates/jcctl/src \
 && echo 'pub fn _dep_cache() {}' > crates/jc-core/src/lib.rs \
 && echo 'fn main() {}' > crates/context-gateway/src/main.rs \
 && echo 'fn main() {}' > crates/jcctl/src/main.rs \
 && cargo build --release --locked --workspace && rm -rf crates/*/src
COPY . .
RUN touch crates/*/src/*.rs && cargo build --release --locked --workspace \
 && strip target/release/context-gateway target/release/jcctl

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /src/target/release/context-gateway /usr/local/bin/context-gateway
COPY --from=build /src/target/release/jcctl /usr/local/bin/jcctl
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/context-gateway"]
