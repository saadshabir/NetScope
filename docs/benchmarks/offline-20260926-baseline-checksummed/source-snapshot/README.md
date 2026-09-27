# Reconstruct this benchmark source

Start from commit `f85891b6a61f611bac90535082f75d88838d27e5` in a clean checkout. If `working-tree.patch` is nonempty, apply it with `git apply --binary`. Then copy the contents of `untracked/` into that checkout, preserving paths. An empty patch means tracked files matched the commit. Verify all hashes against `../source.json` before rebuilding.
