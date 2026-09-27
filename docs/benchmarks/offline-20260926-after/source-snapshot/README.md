# Historical source reconstruction

To reconstruct the NetScope application binary source, start from commit
`f85891b6a61f611bac90535082f75d88838d27e5` in a clean checkout and apply
`application.patch` with `git apply --binary`. Its SHA-256 matches the
`tracked_diff_sha256` recorded in `../source.json`. The saved
`untracked/scripts/perf/workloads.py` matches the generator SHA-256 and
recreates this report's zero-checksum PCAPs.

The other original uncommitted benchmark scripts were recorded only by hash,
not saved. The complete benchmark harness source therefore cannot be
reconstructed from this report. The raw run records and environment remain in
`../results.json` and the run directories. The current runner may be used for a
new experiment, but it will generate different checksummed inputs.
