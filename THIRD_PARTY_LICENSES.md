# Third-party licenses

netconf's own code is licensed under MIT OR Apache-2.0, at the recipient's choice; see
[`LICENSE-MIT`](LICENSE-MIT) and [`LICENSE-APACHE`](LICENSE-APACHE). This file lists what netconf
builds on that is not its own, and the license each part declares. Nothing in the repository
itself is third-party code. `CODE_OF_CONDUCT.md` is adapted from the Contributor Covenant,
version 2.1, as the file itself says.

The license given for each crate is the one the crate itself declares: the `license` field of its
manifest.

## Rust crates

These are not in the repository: cargo fetches them from crates.io. The list covers every package
in `Cargo.lock` except `netconf` itself, with one row per crate name; the versions are in
`Cargo.lock`.

"Used by" says what compiles the crate, on any target platform: `netconf` (a build of the library
without features), `netconf with russh-transport` (only a build with that feature),
`tests and build only` (the dev-dependencies and the build scripts), or `not built` (in
`Cargo.lock`, but no build of netconf on any target compiles it).

| Crate | License | Used by |
|---|---|---|
| adler2 | 0BSD OR MIT OR Apache-2.0 | netconf with russh-transport |
| aead | MIT OR Apache-2.0 | netconf |
| aegis | MIT | netconf |
| aes | MIT OR Apache-2.0 | netconf |
| aes-gcm | Apache-2.0 OR MIT | netconf |
| android_system_properties | MIT OR Apache-2.0 | netconf with russh-transport |
| argon2 | MIT OR Apache-2.0 | netconf |
| async-trait | MIT OR Apache-2.0 | netconf |
| autocfg | Apache-2.0 OR MIT | tests and build only |
| base16ct | Apache-2.0 OR MIT | netconf |
| base64ct | Apache-2.0 OR MIT | netconf |
| bcrypt-pbkdf | MIT OR Apache-2.0 | netconf with russh-transport |
| bitflags | MIT OR Apache-2.0 | netconf with russh-transport |
| blake2 | MIT OR Apache-2.0 | netconf |
| block-buffer | MIT OR Apache-2.0 | netconf |
| block-padding | MIT OR Apache-2.0 | netconf with russh-transport |
| blowfish | MIT OR Apache-2.0 | netconf with russh-transport |
| bumpalo | MIT OR Apache-2.0 | netconf with russh-transport |
| byteorder | Unlicense OR MIT | netconf with russh-transport |
| bytes | MIT | netconf |
| cbc | MIT OR Apache-2.0 | netconf with russh-transport |
| cc | MIT OR Apache-2.0 | tests and build only |
| cfg-if | MIT OR Apache-2.0 | netconf |
| cfg_aliases | MIT | tests and build only |
| chacha20 | MIT OR Apache-2.0 | netconf |
| chacha20poly1305 | Apache-2.0 OR MIT | netconf |
| chrono | MIT OR Apache-2.0 | netconf with russh-transport |
| cipher | MIT OR Apache-2.0 | netconf |
| cmov | Apache-2.0 OR MIT | netconf |
| const-oid | Apache-2.0 OR MIT | netconf |
| core-foundation-sys | MIT OR Apache-2.0 | netconf with russh-transport |
| cpubits | MIT OR Apache-2.0 | netconf |
| cpufeatures | MIT OR Apache-2.0 | netconf |
| crc32fast | MIT OR Apache-2.0 | netconf with russh-transport |
| crypto-bigint | Apache-2.0 OR MIT | netconf |
| crypto-common | MIT OR Apache-2.0 | netconf |
| crypto-primes | Apache-2.0 OR MIT | netconf with russh-transport |
| ctr | MIT OR Apache-2.0 | netconf |
| ctutils | Apache-2.0 OR MIT | netconf |
| curve25519-dalek | BSD-3-Clause | netconf |
| curve25519-dalek-derive | MIT/Apache-2.0 | netconf |
| data-encoding | MIT | netconf with russh-transport |
| delegate | MIT OR Apache-2.0 | netconf with russh-transport |
| der | Apache-2.0 OR MIT | netconf |
| des | MIT OR Apache-2.0 | not built |
| digest | MIT OR Apache-2.0 | netconf |
| dsa | Apache-2.0 OR MIT | netconf with russh-transport |
| ecdsa | Apache-2.0 OR MIT | netconf |
| ed25519 | Apache-2.0 OR MIT | netconf |
| ed25519-dalek | BSD-3-Clause | netconf |
| elliptic-curve | Apache-2.0 OR MIT | netconf |
| enum_dispatch | MIT OR Apache-2.0 | netconf with russh-transport |
| ff | MIT/Apache-2.0 | netconf |
| fiat-crypto | MIT OR Apache-2.0 OR BSD-1-Clause | netconf |
| find-msvc-tools | MIT OR Apache-2.0 | tests and build only |
| flate2 | MIT OR Apache-2.0 | netconf with russh-transport |
| futures | MIT OR Apache-2.0 | netconf with russh-transport |
| futures-channel | MIT OR Apache-2.0 | netconf with russh-transport |
| futures-core | MIT OR Apache-2.0 | netconf with russh-transport |
| futures-executor | MIT OR Apache-2.0 | netconf with russh-transport |
| futures-io | MIT OR Apache-2.0 | netconf with russh-transport |
| futures-macro | MIT OR Apache-2.0 | netconf with russh-transport |
| futures-sink | MIT OR Apache-2.0 | netconf with russh-transport |
| futures-task | MIT OR Apache-2.0 | netconf with russh-transport |
| futures-util | MIT OR Apache-2.0 | netconf with russh-transport |
| generic-array | MIT | netconf with russh-transport |
| getrandom | MIT OR Apache-2.0 | netconf |
| ghash | Apache-2.0 OR MIT | netconf |
| group | MIT/Apache-2.0 | netconf |
| hex | MIT OR Apache-2.0 | netconf with russh-transport |
| hex-literal | MIT OR Apache-2.0 | netconf with russh-transport |
| hkdf | MIT OR Apache-2.0 | netconf |
| hmac | MIT OR Apache-2.0 | netconf |
| hybrid-array | MIT OR Apache-2.0 | netconf |
| iana-time-zone | MIT OR Apache-2.0 | netconf with russh-transport |
| iana-time-zone-haiku | MIT OR Apache-2.0 | netconf with russh-transport |
| inout | MIT OR Apache-2.0 | netconf |
| js-sys | MIT OR Apache-2.0 | netconf with russh-transport |
| keccak | Apache-2.0 OR MIT | netconf with russh-transport |
| kem | Apache-2.0 OR MIT | netconf with russh-transport |
| krypto | MIT OR Apache-2.0 | netconf |
| libc | MIT OR Apache-2.0 | netconf |
| log | MIT OR Apache-2.0 | netconf with russh-transport |
| md5 | Apache-2.0 OR MIT | netconf with russh-transport |
| memchr | Unlicense OR MIT | netconf |
| miniz_oxide | MIT OR Zlib OR Apache-2.0 | netconf with russh-transport |
| mio | MIT | netconf with russh-transport |
| ml-kem | Apache-2.0 OR MIT | netconf with russh-transport |
| module-lattice | Apache-2.0 OR MIT | netconf with russh-transport |
| nix | MIT | netconf with russh-transport |
| num-bigint | MIT OR Apache-2.0 | netconf with russh-transport |
| num-integer | MIT OR Apache-2.0 | netconf with russh-transport |
| num-traits | MIT OR Apache-2.0 | netconf |
| once_cell | MIT OR Apache-2.0 | netconf |
| p256 | Apache-2.0 OR MIT | netconf |
| p384 | Apache-2.0 OR MIT | netconf with russh-transport |
| p521 | Apache-2.0 OR MIT | netconf with russh-transport |
| pageant | Apache-2.0 | netconf with russh-transport |
| password-hash | MIT OR Apache-2.0 | netconf |
| pbkdf2 | MIT OR Apache-2.0 | netconf with russh-transport |
| pem-rfc7468 | Apache-2.0 OR MIT | netconf |
| phc | Apache-2.0 OR MIT | netconf |
| pin-project-lite | Apache-2.0 OR MIT | netconf |
| pkcs1 | Apache-2.0 OR MIT | netconf with russh-transport |
| pkcs5 | Apache-2.0 OR MIT | netconf with russh-transport |
| pkcs8 | Apache-2.0 OR MIT | netconf |
| poly1305 | Apache-2.0 OR MIT | netconf |
| polyval | Apache-2.0 OR MIT | netconf |
| primefield | Apache-2.0 OR MIT | netconf |
| primeorder | Apache-2.0 OR MIT | netconf |
| proc-macro2 | MIT OR Apache-2.0 | netconf |
| quick-xml | MIT | netconf |
| quote | MIT OR Apache-2.0 | netconf |
| r-efi | MIT OR Apache-2.0 OR LGPL-2.1-or-later | netconf |
| rand | MIT OR Apache-2.0 | netconf with russh-transport |
| rand_core | MIT OR Apache-2.0 | netconf |
| rfc6979 | Apache-2.0 OR MIT | netconf |
| ring | Apache-2.0 AND ISC | netconf with russh-transport |
| rsa | MIT OR Apache-2.0 | netconf with russh-transport |
| russh | Apache-2.0 | netconf with russh-transport |
| russh-cryptovec | Apache-2.0 | netconf with russh-transport |
| russh-util | Apache-2.0 | netconf with russh-transport |
| rustc_version | MIT OR Apache-2.0 | tests and build only |
| rustversion | MIT OR Apache-2.0 | netconf with russh-transport |
| salsa20 | MIT OR Apache-2.0 | netconf with russh-transport |
| scrypt | MIT OR Apache-2.0 | netconf with russh-transport |
| sec1 | Apache-2.0 OR MIT | netconf |
| semver | MIT OR Apache-2.0 | tests and build only |
| serde | MIT OR Apache-2.0 | not built |
| serde_core | MIT OR Apache-2.0 | not built |
| serde_derive | MIT OR Apache-2.0 | not built |
| serdect | Apache-2.0 OR MIT | not built |
| sha1 | MIT OR Apache-2.0 | netconf with russh-transport |
| sha2 | MIT OR Apache-2.0 | netconf |
| sha3 | MIT OR Apache-2.0 | netconf with russh-transport |
| shlex | MIT OR Apache-2.0 | tests and build only |
| signature | Apache-2.0 OR MIT | netconf |
| simd-adler32 | MIT | netconf with russh-transport |
| slab | MIT | netconf with russh-transport |
| socket2 | MIT OR Apache-2.0 | netconf with russh-transport |
| softaes | MIT | netconf |
| spki | Apache-2.0 OR MIT | netconf |
| sponge-cursor | MIT OR Apache-2.0 | netconf with russh-transport |
| ssh-cipher | Apache-2.0 OR MIT | netconf with russh-transport |
| ssh-encoding | Apache-2.0 OR MIT | netconf with russh-transport |
| ssh-key | Apache-2.0 OR MIT | netconf with russh-transport |
| subtle | BSD-3-Clause | netconf |
| syn | MIT OR Apache-2.0 | netconf |
| thiserror | MIT OR Apache-2.0 | netconf with russh-transport |
| thiserror-impl | MIT OR Apache-2.0 | netconf with russh-transport |
| tokio | MIT | netconf with russh-transport |
| tokio-macros | MIT | netconf with russh-transport |
| tracing | MIT | netconf |
| tracing-attributes | MIT | netconf |
| tracing-core | MIT | netconf |
| typenum | MIT OR Apache-2.0 | netconf |
| unicode-ident | (MIT OR Apache-2.0) AND Unicode-3.0 | netconf |
| universal-hash | MIT OR Apache-2.0 | netconf |
| untrusted | ISC | netconf with russh-transport |
| wasi | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | netconf with russh-transport |
| wasm-bindgen | MIT OR Apache-2.0 | netconf with russh-transport |
| wasm-bindgen-futures | MIT OR Apache-2.0 | netconf with russh-transport |
| wasm-bindgen-macro | MIT OR Apache-2.0 | netconf with russh-transport |
| wasm-bindgen-macro-support | MIT OR Apache-2.0 | netconf with russh-transport |
| wasm-bindgen-shared | MIT OR Apache-2.0 | netconf with russh-transport |
| windows | MIT OR Apache-2.0 | netconf with russh-transport |
| windows-collections | MIT OR Apache-2.0 | netconf with russh-transport |
| windows-core | MIT OR Apache-2.0 | netconf with russh-transport |
| windows-future | MIT OR Apache-2.0 | netconf with russh-transport |
| windows-implement | MIT OR Apache-2.0 | netconf with russh-transport |
| windows-interface | MIT OR Apache-2.0 | netconf with russh-transport |
| windows-link | MIT OR Apache-2.0 | netconf with russh-transport |
| windows-numerics | MIT OR Apache-2.0 | netconf with russh-transport |
| windows-result | MIT OR Apache-2.0 | netconf with russh-transport |
| windows-strings | MIT OR Apache-2.0 | netconf with russh-transport |
| windows-sys | MIT OR Apache-2.0 | netconf with russh-transport |
| windows-targets | MIT OR Apache-2.0 | netconf with russh-transport |
| windows-threading | MIT OR Apache-2.0 | netconf with russh-transport |
| windows_aarch64_gnullvm | MIT OR Apache-2.0 | netconf with russh-transport |
| windows_aarch64_msvc | MIT OR Apache-2.0 | netconf with russh-transport |
| windows_i686_gnu | MIT OR Apache-2.0 | netconf with russh-transport |
| windows_i686_gnullvm | MIT OR Apache-2.0 | netconf with russh-transport |
| windows_i686_msvc | MIT OR Apache-2.0 | netconf with russh-transport |
| windows_x86_64_gnu | MIT OR Apache-2.0 | netconf with russh-transport |
| windows_x86_64_gnullvm | MIT OR Apache-2.0 | netconf with russh-transport |
| windows_x86_64_msvc | MIT OR Apache-2.0 | netconf with russh-transport |
| wnaf | Apache-2.0 OR MIT | netconf |
| x25519-dalek | BSD-3-Clause | netconf |
| zeroize | Apache-2.0 OR MIT | netconf |
