# BlackArch packaging

This directory contains the package template intended for a future BlackArch pull request.

1. Publish the project at a Git host and create a `v0.1.0` tag.
2. Replace `REPLACE_WITH_GITHUB_USER` in `PKGBUILD.blackarch`.
3. Rename it to `PKGBUILD` inside a package directory named `elfscope`.
4. Build and test with `makepkg`.
5. Run BlackArch's `pkgcheck` script before opening the pull request.
6. Review the generated package with `namcap` as an additional Arch packaging sanity check.

The proposed initial groups are `blackarch`, `blackarch-binary`, and `blackarch-reversing`. The final group selection remains subject to BlackArch maintainer review.
