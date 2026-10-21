# Device builds with Metal libraries

Run a development or ad-hoc device app with `simrun run path/to/App.app`.
SimRun converts a disposable copy. Encrypted App Store executables are unsupported.

Metal conversion requires Xcode's Metal toolchain (`metal-opt`, `metallib`,
`metal-objdump`, `metal-nm` and, for empty libraries, `metal-vtool`). Install the
Metal toolchain through Xcode if these tools are unavailable.

The converter retargets embedded AIR from iOS to iOS Simulator and relinks each
`.metallib`. It verifies unchanged shader IR apart from the target triple and
unchanged exported symbols. Libraries with unsupported bitcode or incompatible
tools fail conversion with an error; their shaders are never replaced.

Original entitlement declarations are placed in `__TEXT,__entitlements`, as in
Xcode Simulator builds. The host code signature is still ad hoc and carries no
restricted entitlements. Enough unused Mach-O header padding must exist; original
code sections are not moved. This metadata preserves app-group and CloudKit
container discovery but does not supply accounts, credentials or working remote
services. Unsigned apps have no declarations to preserve and remain supported.

Set `SIMRUN_DEVICE_CACHE` on the server process to use a separate conversion cache.
An isolated development run can also set `SIMRUN_SERVER`, `SIMRUND_SOCKET` and
`SIMRUN_DATA`; this does not replace the installed SimRun.

Run converter tests from the repository root:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests/scripts -p 'test_*.py' -v
```

The Metal integration test compiles a small device shader with the installed
Apple toolchain, converts it, checks its Simulator platform and verifies repeat
conversion leaves it unchanged.
