FROM rust:1.62.0-bullseye as build-env
WORKDIR /app
COPY . /app
RUN cargo build --release

FROM gcr.io/distroless/cc
COPY --from=build-env /app/target/release/reverse-proxy /

CMD ["/reverse-prox"] 