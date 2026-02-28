# tcputils (Go)

A TCP troubleshooting utility written in Go.

This project is similar to classic `tcptraceroute`, with practical upgrades for network/DevOps diagnostics:

- Per-hop packet loss (`loss%`)
- Min/avg/max RTT statistics per hop
- Optional reverse DNS caching (`--no-rdns` to disable)
- Optional diagnostics mode (`--diag`) for:
  - DNS resolution timing and IP inventory
  - TCP connect latency and failure rate across attempts
  - TLS handshake + certificate metadata
  - HTTP probe (status, TTFB, timing)
- Optional TCP ping mode (`--tcpping`) with latency stats (min/avg/max, p95, jitter, loss)
- Optional JSON output (`--json`) for automation
- Clean single-binary CLI

## Requirements

- macOS/Linux
- Go 1.22+
- Root/admin privileges (raw sockets are required)

## Build

```bash
go build -o tcputils ./cmd/tcputils
```

## Run

```bash
sudo tcputils -p 443 -m 20 github.com
```

## Examples

### 1) Basic TCP traceroute (HTTPS)

```bash
sudo tcputils -p 443 -m 20 github.com
```

### 2) Faster live output (fewer probes, short timeout)

```bash
sudo tcputils -p 443 -m 20 --no-rdns -q 1 -w 1s github.com
```

### 3) Start from a specific hop

```bash
sudo tcputils -p 443 -f 5 -m 20 github.com
```

### 4) Run diagnostics + traceroute together

```bash
sudo tcputils --diag -p 443 -m 20 --no-rdns -q 1 -w 1s github.com
```

### 4.1) Run TCP ping latency probes

```bash
tcputils --tcpping --tcpping-count 10 --tcpping-interval 500ms --tcpping-timeout 2s -p 443 github.com
```

### 4.2) TCP ping only (skip diagnostics/traceroute)

```bash
tcputils --tcpping-only --tcpping-count 20 -p 443 github.com
```

### 4.3) Continuous TCP latency monitoring (until Ctrl+C)

```bash
tcputils --tcpping --tcpping-forever --tcpping-interval 1s -p 443 api.example.com
```

### 4.4) Continuous mode with hard deadline

```bash
tcputils --tcpping --tcpping-forever --tcpping-deadline 2m --tcpping-interval 1s -p 443 api.example.com
```

### 5) Diagnostics only (no traceroute, no root required)

```bash
tcputils --diag-only -p 443 github.com
```

### 6) Increase TCP connect sample size in diagnostics

```bash
tcputils --diag-only -p 443 --connect-attempts 10 --connect-timeout 1s github.com
```

### 7) Force TLS check on non-443 service

```bash
tcputils --diag-only --tls -p 8443 example.com
```

### 8) Override SNI for TLS troubleshooting

```bash
tcputils --diag-only --tls --sni api.example.com -p 443 203.0.113.10
```

### 9) Skip TLS cert verification for testing only

```bash
tcputils --diag-only --tls -k -p 443 badcert.example.com
```

### 10) HTTP probe with auto URL (uses https on port 443)

```bash
tcputils --diag-only --http -p 443 github.com
```

### 11) HTTP probe with custom URL and method

```bash
tcputils --diag-only --http-url https://github.com/login --http-method HEAD github.com
```

### 12) Increase HTTP timeout for slow endpoints

```bash
tcputils --diag-only --http --http-timeout 15s -p 443 github.com
```

### 13) JSON output (diagnostics + trace)

```bash
sudo tcputils --diag --json -p 443 -m 20 github.com
```

### 13.1) JSON output (TCP ping + trace)

```bash
tcputils --tcpping --json -p 443 -m 10 github.com
```

### 14) JSON output (diagnostics only)

```bash
tcputils --diag-only --json --http -p 443 github.com
```

### 15) Trace non-HTTPS ports (SMTP, SSH, custom app)

```bash
sudo tcputils -p 25 -m 20 mail.example.com
sudo tcputils -p 22 -m 20 ssh.example.com
sudo tcputils -p 8443 -m 20 app.example.com
```

### Common flags

- `-p` destination TCP port (default: `80`)
- `-m` max hops (default: `30`)
- `-f` first hop TTL (default: `1`)
- `-q` probes per hop (default: `3`)
- `-w` timeout per probe (default: `2s`)
- `--no-rdns` disable reverse DNS lookups
- `--json` output full trace in JSON
- `--diag` run DNS/TCP/TLS/HTTP diagnostics before trace
- `--diag-only` run diagnostics and skip traceroute
- `--tcpping` run TCP ping latency probes
- `--tcp-latency` alias for `--tcpping`
- `--tcpping-only` run TCP ping and skip diagnostics/traceroute
- `--tcpping-count` number of TCP ping probes (default: `5`)
- `--tcpping-interval` interval between TCP ping probes (default: `1s`)
- `--tcpping-timeout` timeout per TCP ping probe (default: `2s`)
- `--tcpping-forever` run TCP ping until interrupted
- `--tcpping-deadline` stop TCP ping after total runtime (for batch monitoring windows)
- `--connect-attempts` TCP connect attempts for diagnostics (default: `3`)
- `--connect-timeout` timeout for each diagnostics TCP connect (default: `2s`)
- `--tls` force TLS diagnostics (auto-enabled when `-p 443`)
- `--sni` override TLS ServerName/SNI in diagnostics
- `-k` skip TLS verification in diagnostics
- `--http` run HTTP probe in diagnostics
- `--http-url` custom URL for HTTP probe
- `--http-method` HTTP method for probe (default: `GET`)
- `--http-timeout` timeout for HTTP probe (default: `8s`)

## Notes

- This implementation currently supports IPv4.
- If you run without privileges, socket creation will fail.

## Production TCP Use-Cases

### Distinguish network path vs app/service issue

- Run latency probes first: `tcputils --tcpping-only -p 443 --tcpping-count 20 api.example.com`
- If TCP is stable but requests fail, run HTTP/TLS diagnostics: `tcputils --diag-only --http -p 443 api.example.com`

### Detect intermittent packet loss or jitter spikes

- `tcputils --tcpping --tcpping-forever --tcpping-interval 1s -p 443 api.example.com`
- Use output `loss`, `p95`, and `jitter` to correlate with incident windows.

### Validate TLS/SNI routing behind load balancers

- `tcputils --diag-only --tls --sni api.example.com -p 443 <lb-or-ingress-ip>`
- Confirms handshake success and certificate details for the requested SNI.

### Trace difficult paths after a connectivity change

- `sudo tcputils -p 443 -m 30 --no-rdns -q 1 -w 1s api.example.com`
- Helps identify where the path starts timing out.

## Release (GoReleaser)

This repo includes:

- `.goreleaser.yml` for multi-platform builds (`linux`, `darwin`, `windows`, `freebsd` on `amd64` and `arm64`)
- `.github/workflows/release.yml` to publish a GitHub Release when a `v*` tag is pushed

### Local dry-run

```bash
goreleaser release --snapshot --clean
```

### Publish a release

```bash
git tag v0.1.0
git push origin v0.1.0
```

GitHub Actions will build archives, generate checksums, and create the release artifacts automatically.
