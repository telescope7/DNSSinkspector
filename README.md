# DNSSinkspector

Command-line DNS sinkhole service in Java.

It listens for DNS queries over UDP, matches domains from a TOML config, returns configured sinkhole A records, and writes structured events for analysis.
It also includes a JDK HttpServer-based HTTP listener (HTTPS-ready), an Apache FtpServer-based FTP listener, and an Apache James-based SMTP listener for credential/request capture and logging.

## Features
- UDP DNS listener (default port `5300`)
- HTTP listener built on JDK HttpServer (default port `80`, optional HTTPS)
- FTP listener built on Apache FtpServer (default port `21`)
- SMTP listener built on Apache James protocols (default port `25`)
- TOML-driven multi-domain zone rules
- Exact and subdomain matching (`a.b.example.com` can match `example.com`)
- Configurable fallback behavior (`NXDOMAIN` or `NODATA`)
- Structured logs in both JSONL and TSV for analytics pipelines (R, Python, SIEM)

## Config
Sample config: [`config/sinkhole.toml`](config/sinkhole.toml)

Key settings:
- `[server]`
- `[http]`, `[smtp]`, `[ftp]`
- `[[zones]]` entries (one per domain)

HTTPS support is configured under `[http]` using:
- `tls_enabled`
- `tls_keystore_path`
- `tls_keystore_password`
- `tls_key_password` (optional, defaults to keystore password)
- `tls_keystore_type` (default `PKCS12`)

Protocol listeners default to disabled unless `enabled = true`.

## Build
```bash
mvn -DskipTests clean package
```

## Run
```bash
java -jar target/dnssinkspector-1.0.0.jar --config config/sinkhole.toml
```

## Build Dist Bundle
Create a runnable distribution with:
- JAR in `lib/`
- shell runner in `bin/run.sh`
- default config in `config/`
- archives in both `.zip` and `.tar.gz`

```bash
./scripts/build-package-distribute.sh
```

Optional custom Maven repo location:
```bash
MAVEN_REPO_LOCAL=/path/to/repo ./scripts/build-package-distribute.sh
```

Artifacts are written to:
```bash
dist/dnssinkspector-1.0.0.zip
dist/dnssinkspector-1.0.0.tar.gz
```

Run from extracted bundle:
```bash
./bin/run.sh
```

Note: ports below `1024` (`80/25/21`) usually require elevated privileges. For local unprivileged testing, set higher ports (for example `8080/2525/2121`) in TOML.

## Test with dig
In another terminal:
```bash
dig @127.0.0.1 -p 5300 malware-test.local A
dig @127.0.0.1 -p 5300 sub.example-botnet.local A
dig @127.0.0.1 -p 5300 unknown-domain.local A
```

## Test TCP listeners
```bash
curl -v http://127.0.0.1:8080/
curl -vk https://127.0.0.1:8443/   # when [http].tls_enabled = true
printf "USER test\r\nPASS secret\r\nQUIT\r\n" | nc 127.0.0.1 2121
printf "EHLO local\r\nAUTH LOGIN\r\ndGVzdHVzZXI=\r\nc2VjcmV0\r\nQUIT\r\n" | nc 127.0.0.1 2525
```

## Log output
Events are appended to full logs:
- `logs/events.jsonl`
- `logs/events.tsv`

And sanitized logs:
- `logs/events-clean.jsonl`
- `logs/events-clean.tsv`

Important fields:
- `timestamp_utc`
- `protocol`, `transport`
- `client_ip`, `client_port`
- `server_ip`, `server_port`
- `query_name`, `query_type_name`
- `matched_zone`, `zone_tags`
- `decision`, `response_rcode_name`
- `answer_ipv4`
- `username`, `password`
- `data_text`, `data_base64`
- `latency_ms`
- `request_size_bytes`, `response_size_bytes`

Sanitized logs exclude `data_text` and `data_base64` to simplify analysis in R.
TSV output is intended for direct use in R via `read.delim()` / `readr::read_tsv()`.
