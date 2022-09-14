# Reverse proxy for Tor

This is a minimal reverse proxy that makes it possible to make apps tat are only available over Tor available on the "normal" internet.

It currently uses a SOCKS proxy, but support for the native Rust Tor (arti) is planned once it supports hidden services.

We use Supabase for account management.

This proxy currently only supports HTTP and WebSockets, but more protocols will be added in the future.

SSL management is currently handled by Cloudflare, but we will later implement support for the ACME protocol.

This server also implements Prometheus monitoring.
