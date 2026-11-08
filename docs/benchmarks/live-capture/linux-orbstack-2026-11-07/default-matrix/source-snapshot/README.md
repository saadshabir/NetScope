# Reconstruct this benchmark source

Start from commit `e938017a7d86dc942e5cedf80975191b458bfd4a` in a clean checkout. If `working-tree.patch` is nonempty, apply it with `git apply --binary`. Then copy the contents of `untracked/` into that checkout, preserving paths. An empty patch means tracked files matched the commit. Verify all hashes against `../source.json` before rebuilding.
