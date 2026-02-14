# C-Go bindings

This package contains C bindings used by Go components when interacting with low-level unikernel internals.

It is primarily intended for advanced internal integrations and runtime/packaging paths.

Current state:
- APIs under `v0` are explicitly unstable.
- Symbols and helpers may change between releases.

Import path:

```go
import "unikctl.sh/unikraft/export/v0"
```

Use this package only when you need direct low-level access; prefer higher-level abstractions in the rest of the codebase.
