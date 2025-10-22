# fips204_rs

Pure Rust implementation of the [FIPS 204] Module-Lattice-Based Digital Signature Standard .

See <https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.204.pdf> for a full description of the target functionality.

## Security warnings

The implementation contained in this crate has never been independently audited!

USE AT YOUR OWN RISK!


## Examples

The functionality is extremely simple to use, as demonstrated by the following example.

(See `integration.rs` for the full example.)

```rust
use fips204_rs::{KeyGen, MlDsa44, SerDes, Signer, Verifier};  // Could also be MlDsa65 or MlDsa87.

    let message = [0u8, 1, 2, 3, 4, 5, 6, 7];

    // Generate key pair and signature
    let (pk1, sk) = MlDsa44::try_keygen().unwrap(); // Generate both public and secret keys
    let sig = sk.try_sign(&message, &[]).unwrap(); // Use the secret key to generate a message signature

    // Serialize then send the public key, message and signature
    let (pk_send, msg_send, sig_send) = (pk1.into_bytes(), message, sig);
    let (pk_recv, msg_recv, sig_recv) = (pk_send, msg_send, sig_send);

    // Deserialize the public key and signature, then verify the message
    let pk2 = <MlDsa44 as KeyGen>::PublicKey::try_from_bytes(&pk_recv).unwrap();
    let v = pk2.verify(&msg_recv, &sig_recv, &[]); // Use the public to verify message signature
    assert!(v);

```

## License

Licensed under either of

* [MIT license](http://opensource.org/licenses/MIT)
* [Apache License, Version 2.0](http://www.apache.org/licenses/LICENSE-2.0)

at your option.

Copyright 2025 [John-Yu](https://github.com/John-Yu).

### Thanks

This was inspired by [fips204](https://github.com/integritychain/fips204).
which is an outstanding project developed by [Eric Schorn](<eschorn@integritychain.com>).

I implemented a new interface with the following changes:
 - Updated traits.rs and ml_dsa.rs.
 - Rewrote lib.rs.

Thanks to Eric Schorn.

### Benchmark

(OS: windows11 24H2, CPU: Intel® Core™  i7-8700K 3.70GHz, See `benchmark.rs` for the details)

| function | times |
|:-:|:-:|
| ml_dsa_44 keygen |time:   [113.13 µs 113.30 µs 113.53 µs] |
| ml_dsa_65 keygen |time:   [200.16 µs 200.36 µs 200.60 µs] |
| ml_dsa_87 keygen |time:   [298.31 µs 298.52 µs 298.78 µs] |
| ml_dsa_44 sk sign |time:   [295.14 µs 297.91 µs 300.87 µs] |
| ml_dsa_65 sk sign |time:   [476.08 µs 481.52 µs 487.08 µs] |
| ml_dsa_87 sk sign |time:   [590.45 µs 596.85 µs 603.41 µs] |
| ml_dsa_44 pk verify |time:   [81.748 µs 81.793 µs 81.840 µs] |
| ml_dsa_65 pk verify |time:   [136.72 µs 136.98 µs 137.32 µs] |
| ml_dsa_87 pk verify |time:   [236.14 µs 236.57 µs 237.14 µs] |

### Authors

* [John-Yu](https://github.com/John-Yu)

### Contribution

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
license, shall be dual licensed as above, without any additional terms or
conditions.

[//]: # (general links)

[FIPS 204]: https://csrc.nist.gov/pubs/fips/204/final
