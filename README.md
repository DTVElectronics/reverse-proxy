# Reverse proxy for Tor

This is a minimal reverse proxy that makes it possible to make apps tat are only available over Tor available on the "normal" internet.

It currently uses a SOCKS proxy, but support for the native Rust Tor (arti) is planned once it supports hidden services.

To manage users, Supabase is used. In addition, we use Redis to cache results from Supabase.

This proxy currently oly supports HTTP and WebSockets, but more protocols will be added in the future.

SSL managment is currently handled by Cloudflare, but we will later implement support for the ACME protocol.
