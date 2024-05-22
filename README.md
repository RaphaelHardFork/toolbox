# Rust toolbox

*A collection of small tools implemented in Rust to discover the specificities of the language and its libraries.*

## Crates:
- `sha1-cracker` - [SHA1 password cracker](./crates/sha1-cracker/)
- `simple-scanner` - [Synchronous ports scanner](./crates/simple-scanner/) using `ureq` & `rayon`
- `scanner` - [Ports and vulnerabilities scanner](./crates/scanner/) using `tokio` & `reqwest`

## Usage:

Run any crates with:
```zsh
cargo run -p <crate_name> <commands>
```