# Rust toolbox

- [SHA1 password cracker](./crates/sha1-cracker/)
- [Synchronous ports scanner](./crates/simple-scanner/) using `ureq` & `rayon`
- [Ports and vulnerabilities scanner](./crates/scanner/) using `tokio` & `reqwest`

Run any crates with:
```zsh
cargo run -p <crate_name> <commands>
```