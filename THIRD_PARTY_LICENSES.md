# Third-Party Licenses

tripwyre is distributed with the following open-source components. Their
licenses are permissive and permit commercial, closed-source redistribution,
provided this attribution and the license texts are preserved. Full license
texts are available at the linked repositories and in the Go module cache.

| Component | Version | License | Source |
|-----------|---------|---------|--------|
| github.com/spf13/cobra | v1.8.0 | Apache-2.0 | https://github.com/spf13/cobra |
| github.com/spf13/pflag | v1.0.5 | BSD-3-Clause | https://github.com/spf13/pflag |
| github.com/inconshreveable/mousetrap | v1.1.0 | Apache-2.0 | https://github.com/inconshreveable/mousetrap |
| github.com/BurntSushi/toml | v1.3.2 | MIT | https://github.com/BurntSushi/toml |

When adding a dependency, add a row here and confirm its license is on the
permissive allowlist (MIT, Apache-2.0, BSD-2/3-Clause, ISC). Copyleft licenses
(GPL, AGPL, LGPL for statically linked Go) are incompatible with proprietary
distribution of this binary.

At release time, regenerate and verify with:

```
go run github.com/google/go-licenses@latest report ./...
```
