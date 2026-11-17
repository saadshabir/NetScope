# Fuzzing NetScope

Use a nightly Rust toolchain, `cargo-fuzz`, a C++ toolchain, and libpcap as for a headless NetScope build.

```sh
rustup toolchain install nightly
cargo install cargo-fuzz --locked
cargo +nightly fuzz list
```

Run a bounded smoke test from the project root. The first corpus directory holds locally discovered inputs. The second holds the checked-in synthetic seeds.

```sh
for target in packet_parse dns_compression tls_lengths routing_consistency; do
    mkdir -p "fuzz/corpus/$target"
    cargo +nightly fuzz run "$target" "fuzz/corpus/$target" "fuzz/seeds/$target" \
        -- -runs=10000 -max_len=32768 || exit 1
done
```

| Target | Coverage |
| --- | --- |
| `packet_parse` | Whole frames across all supported link types, including packet summaries and application decoding. |
| `dns_compression` | Names in questions, record owners, and name-bearing RDATA across DNS sections. |
| `tls_lengths` | Single-record ClientHello and SNI parsing, including nested lengths, truncation, and trailing bytes. |
| `routing_consistency` | Shard bounds for arbitrary frames. Parsed IPv4 and IPv6 TCP/UDP traffic must route identically in both directions and across link encapsulations, including QinQ. The first input byte selects a shard count, followed by packet bytes. |

For a longer session, remove `-runs` or use `-max_total_time=<seconds>`. LibFuzzer writes failures under `fuzz/artifacts/<target>/`. Pass an artifact path in place of the corpus directories to replay it locally. [Rust Fuzz Book](https://rust-fuzz.github.io/book/cargo-fuzz/guide.html)
