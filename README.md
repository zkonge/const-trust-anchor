# const-pki-types

Converting X.509 certificates to the TrustAnchor in rustls-pki-types at compile time

The usage is same as [webpki::anchor_from_trusted_cert](https://docs.rs/rustls-webpki/latest/webpki/fn.anchor_from_trusted_cert.html), name constraints are preserved. Only X.509 v3 certificates are supported.

```rust
use const_pki_types::{TrustAnchor, anchor_from_trusted_cert};

const MY_ROOT: TrustAnchor<'static> = anchor_from_trusted_cert(include_bytes!("my_root.der"));
```

A malformed certificate becomes a compile error. Use `try_anchor_from_trusted_cert` to get a `Result` instead.

The parser is strict DER, made for the pedantic: minimal length encoding, no explicit `critical FALSE`, nothing after the last field. Some non-DER certificates that webpki tolerates are rejected here.

The certificate is not validated, only use certificates you trust.

## Converting PEM certificate to TrustAnchor?

You may also need [const-decoder::decode](https://docs.rs/const-decoder/0.4.0/const_decoder/macro.decode.html#usage-with-pem)
