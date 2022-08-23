FROM rust:1.62.0-bullseye as build-env
WORKDIR /app

RUN cargo init

COPY Cargo.lock Cargo.toml .

RUN cargo build --release

RUN rm -rf src

COPY src src

COPY build.rs .

RUN cargo build --release

FROM gcr.io/distroless/cc
COPY --from=build-env /app/target/release/reverse-proxy /

CMD ["/reverse-proxy"] 
