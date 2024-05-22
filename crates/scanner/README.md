# Asynchronous ports and vulnerabilities scanner

## Usage

List modules:
```zsh
cargo run modules
```

Scan a domain:
```zsh
cargo run scan <domain>
```

## Details

The function [`scan`](./src/scan.rs) contain all the logic to scan a domain broken down into three steps:
1. Scan subdomains using https://crt.sh and https://web.archive.org and try to resolve them.
2. Scan [most common ports*](./src/ports.rs) of each subdomain resolved.
3. For each open ports send HTTP requests with various endpoints to detect vulnerabilities.

Logs of runs can be saved and output format can be chosen, see with:
```zsh
cargo run scan --help
```

Scanning vulnerabilities is ineficient because for each port multiple HTTP request are sent to the same endpoint (`http://subdomain:port/`). Each module with this endpoint should work on the same `reqwest::Response` but this latter is not clonable.

---

**Ports can be reduced to few in `ports.rs` to make shorter runs.*

