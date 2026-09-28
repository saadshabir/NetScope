# Reconstruct the measured application

Start from commit `f85891b6a61f611bac90535082f75d88838d27e5` in a clean checkout. Apply `application.patch` with `git apply --binary` if it is nonempty, then copy the contents of `untracked/` into that checkout, preserving paths. An empty application patch means the application matched the commit. Build with `cargo build --locked --release`.

## Published evidence

The application patch retains the measured Rust changes exactly. Unrelated documentation hunks and one documentation status entry were omitted. Harness copies preserve workload generation and measurement behavior; diagnostic labels were normalized, and report/schema handling was extended to recognize this publication metadata. Historical build-directory labels in archived paths and build output were also normalized. Packet and byte counts, resource readings, validations, PCAP hashes, and original source and binary fingerprints were retained.

`../source.json` keeps the original measured-worktree fingerprint and original untracked-file hashes as historical identifiers. They do not hash the edited publication copies or reconstruct the omitted documentation. Its `snapshot.complete` is therefore false; `snapshot.application_complete` is true. Verify the files in this directory against `published-manifest.json`, whose hashes describe the public copies.

Historical binary paths may no longer exist. For supplemental runs, use the current `scripts/perf/repeat_scenarios.py --binary <PATH>` with a saved binary whose SHA-256 matches the report. If no matching binary is available, run a new suite.
