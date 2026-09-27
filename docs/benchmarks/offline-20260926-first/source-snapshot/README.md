# Historical source reconstruction

The NetScope application binary in this report was built from commit
`f85891b6a61f611bac90535082f75d88838d27e5` with no tracked application
changes. `application.patch` is intentionally empty. The saved
`untracked/scripts/perf/workloads.py` matches the generator SHA-256 in
`../source.json` and recreates this report's zero-checksum PCAPs.

The original uncommitted runner and result-schema revisions were recorded only
by hash, not saved. The complete benchmark harness source therefore cannot be
reconstructed from this report. The raw run records and environment remain in
`../results.json` and the run directories. The current runner may be used for a
new experiment, but it will generate different checksummed inputs.
