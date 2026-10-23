# Benchmarks

Measured on 2026-10-23 on a laptop (Intel Core i5-1135G7, 4 cores, 16 GB,
Linux under WSL 2), idle, with `make bench-cli` and `make web-perf`.
Numbers vary by about 20% between runs; the shape matters more than the
digits.

## CLI

Synthetic accounts from `escalint synth --principals N --seed 7
--escalation-rate 0.02` (users, groups and roles; 2% of principals hold a
planted escalation primitive). Wall time and peak resident memory from GNU
`time`; output with `--deterministic`.

| Principals | Command | Wall time (s) | Peak RSS (MB) | Output (MB) |
| ---: | --- | ---: | ---: | ---: |
| 1,000 | `analyze` | 0.2 | 47 | 3 |
| 1,000 | `scan -f json` | 0.2 | 46 | 0.5 |
| 1,000 | `scan -f sarif` | 0.2 | 50 | 0.7 |
| 10,000 | `analyze` | 2.2 | 188 | 52 |
| 10,000 | `scan -f json` | 2.0 | 191 | 13 |
| 10,000 | `scan -f sarif` | 2.1 | 202 | 19 |
| 50,000 | `analyze` | 28 | 1,300 | 574 |
| 50,000 | `scan -f json` | 29 | 1,332 | 184 |
| 50,000 | `scan -f sarif` | 28 | 1,331 | 269 |

The 50,000-principal account has 50,008 nodes, 209,729 edges, 1,631
enumerated paths and 185,077 findings: far denser in escalation than a real
account, which is the point of the test. Peak memory is dominated by the
graph and the findings; outputs are streamed to the file (encoding them in
memory first used to double the peak: 2.3 GB for `scan -f json` before
`perf(report)`).

Reproduce:

```sh
make bench-cli                         # 1k, 10k, 50k
make bench-cli BENCH_SIZES="1000 5000"
go test -tags noui -run '^$' -bench . -benchmem ./internal/engine/ ./internal/analysis/ ./internal/eval/
```

The nightly workflow runs the Go benchmarks five times and compares them
with the previous run (`benchstat`).

## Web UI

Playwright in headless Chromium against the production build (`make
web-perf`), synthetic `analysis.json` documents.

| Measure | Data | Result | Budget |
| --- | --- | --- | --- |
| Initial JavaScript | — | 78.8 KB gzip (14 lazy chunks) | 300 KB |
| Overview useful after the data arrives | 10,000 principals | 1.2 s | 2 s |
| Atlas median frame while panning | 10,000 principals | 16.7 ms, no long tasks | 33 ms |
| Longest frame gap, load to interactive Atlas | 50,000 principals | 250 ms over 837 frames | the page keeps rendering |

With more than 10,000 nodes the Atlas shows a notice that explains how it
degrades: the layout takes longer, zoomed out every account is one
meta-node, and labels are kept to the most important principals in view.
The Exposure matrix draws only the rows on screen, and the table behind
every graph is capped and sorted by tier and blast radius.
