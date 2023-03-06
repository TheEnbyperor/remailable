FROM rustlang/rust:nightly AS builder
RUN apt-get update && apt-get install -y musl-tools
RUN mkdir /new_tmp
WORKDIR /usr/src/
RUN rustup target add x86_64-unknown-linux-musl

RUN USER=root cargo new remailable-rust
WORKDIR /usr/src/remailable-rust

COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY .git ./.git
RUN cargo install --target x86_64-unknown-linux-musl --path .

FROM scratch

COPY --from=builder --chown=0:0 /usr/local/cargo/bin/remailable /
COPY --from=builder --chown=0:0 /new_tmp /tmp

ENTRYPOINT ["/remailable"]
