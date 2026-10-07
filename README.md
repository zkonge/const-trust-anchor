# const-trust-anchor

X.509 DER → `rustls_pki_types::TrustAnchor`, in `const`.

```rust
use const_trust_anchor::{TrustAnchor, anchor_from_trusted_cert};

const ROOT: TrustAnchor<'static> = anchor_from_trusted_cert(include_bytes!("root.der"));
```

- `const fn` port of [`webpki::anchor_from_trusted_cert`](https://docs.rs/rustls-webpki/latest/webpki/fn.anchor_from_trusted_cert.html), name constraints included
- bad cert = compile error; `try_anchor_from_trusted_cert` if you want a `Result`
- `no_std`, no alloc, zero deps besides `rustls-pki-types`
- X.509 v3 only
- strict DER, for the pedantic: minimal lengths, no explicit `critical FALSE`, no trailing bytes. Some sloppy certs webpki tolerates get rejected here

Not a validator. Signatures, validity, everything else: unchecked. Feed it certs you already trust.

Got PEM? [`const_decoder::decode!`](https://docs.rs/const-decoder/0.4.0/const_decoder/macro.decode.html#usage-with-pem).
