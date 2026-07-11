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
| github.com/anthropics/anthropic-sdk-go | v1.57.0 | MIT | https://github.com/anthropics/anthropic-sdk-go |
| github.com/tidwall/gjson | v1.18.0 | MIT | https://github.com/tidwall/gjson |
| github.com/tidwall/sjson | v1.2.5 | MIT | https://github.com/tidwall/sjson |
| github.com/tidwall/match | v1.1.1 | MIT | https://github.com/tidwall/match |
| github.com/tidwall/pretty | v1.2.1 | MIT | https://github.com/tidwall/pretty |
| github.com/buger/jsonparser | v1.1.2 | MIT | https://github.com/buger/jsonparser |
| github.com/invopop/jsonschema | v0.14.0 | MIT | https://github.com/invopop/jsonschema |
| github.com/bahlo/generic-list-go | v0.2.0 | BSD-3-Clause | https://github.com/bahlo/generic-list-go |
| github.com/pb33f/ordered-map/v2 | v2.3.1 | Apache-2.0 | https://github.com/pb33f/ordered-map |
| github.com/standard-webhooks/standard-webhooks/libraries | v0.0.1 | MIT | https://github.com/standard-webhooks/standard-webhooks |
| go.yaml.in/yaml/v4 | v4.0.0-rc.2 | MIT / Apache-2.0 | https://github.com/yaml/go-yaml |
| golang.org/x/sync | v0.16.0 | BSD-3-Clause | https://pkg.go.dev/golang.org/x/sync |

When adding a dependency, add a row here and confirm its license is on the
permissive allowlist (MIT, Apache-2.0, BSD-2/3-Clause, ISC). Copyleft licenses
(GPL, AGPL, LGPL for statically linked Go) are incompatible with proprietary
distribution of this binary.

At release time, regenerate and verify with:

```
go run github.com/google/go-licenses@latest report ./...
```
