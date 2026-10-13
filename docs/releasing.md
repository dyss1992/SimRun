# Signed releases

Pushing a tag runs `.github/workflows/release.yml`: build, Developer ID signing, notarization, ticket stapling,
signature/Gatekeeper validation, then publication of the final zip. A failure stops publication. Local `make core`
continues to use ad-hoc signing.

Same-repository PRs that change the release workflow/scripts/entitlements run the same pipeline, as do manual
workflow runs. These save the signed, stapled zip as an Actions artifact without publishing a GitHub Release.
Fork PRs are skipped. Only a pushed tag can publish a Release.

The repository needs these Actions secrets:

| Secret | Value |
| --- | --- |
| `DEVELOPER_ID_P12_BASE64` | Base64 of the Developer ID Application certificate exported with its private key |
| `DEVELOPER_ID_P12_PASSWORD` | The export password |
| `APPLE_API_KEY_P8` | Full text of an App Store Connect team API private key, including PEM header and footer |
| `APPLE_API_KEY_ID` | Key ID |
| `APPLE_API_ISSUER_ID` | Team key's issuer UUID |

The workflow uses `Developer ID Application: Yuxin Chen (V8K4KDZ2JN)`. The notarization key must have access to
that team. No App Store Connect app record is needed. The job imports the certificate into a temporary keychain,
grants codesign access, and deletes the keychain and credential files on exit. The runner needs access to Apple's
timestamp and notarization services as well as GitHub.

## Bundle signing

`tools/sign-release.sh` signs `app.dylib`, `xpcservices.dylib`, `SimFramebuffer`, the Simulator executable `simns`,
the macOS CLI, then the outer app. It verifies every Mach-O's Developer ID signature, hardened runtime and secure
timestamp, including libraries under `Contents/Resources`. New payloads must be added to the signing sequence;
do not replace this with `codesign --deep` signing.

`simns` resides under `Contents/Resources/lib` with the other Simulator-platform payloads, not under the macOS
`Contents/Helpers` code location. Apple's notary service excludes Simulator-platform binaries from its ticket;
classifying `simns` as nested macOS code causes Gatekeeper's deep policy check to reject the outer app even when
notarization and stapling succeed. It remains explicitly signed and sealed by the outer resource signature.

The host has the audio-input entitlement for microphone access. `simns` has allow-dyld-environment-variables
because runtime selection depends on `DYLD_ROOT_PATH` and related variables. Injected libraries do not receive
executable entitlements: they execute under the target app's policy. This workflow does not re-sign users' apps
or Apple's Simulator runtime, or add App Sandbox, get-task-allow, or blanket library-validation/JIT exceptions.

After building, check signing locally with the identity in the login keychain:

```sh
SIGNING_IDENTITY='Developer ID Application: Yuxin Chen (V8K4KDZ2JN)' \
  bash tools/sign-release.sh build/SimRun.app
```

Signing alone does not prove runtime compatibility. Exercise a Simulator app using the signed bundle, including
`simns` startup, injected scripting and rendering. Microphone, WebKit and device-build conversion need their own
runtime checks. Test the downloaded release's first launch with Gatekeeper enabled. Notarization does not remove
SimRun's documented system/runtime prerequisites.

## Diagnostics

The job saves `build/notarization/*.json` as an Actions artifact even on failure. `submission.json` contains the
submission ID, `result.json` the wait result, and `log.json` Apple's findings when available. Submission and waiting
are separate so a timeout retains the ID. Waiting is limited to 30 minutes; Apple may continue processing after a
timeout, but the job does not publish an unconfirmed result. Investigate with `notarytool info` / `log` and that ID.

The zip submitted to Apple is temporary; the release zip is created after stapling and contains the ticket.
Older release downloads may still be unsigned/unnotarized. This workflow only affects tags built with it.

References: [Apple's notarization workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow)
and [common notarization issues](https://developer.apple.com/documentation/security/resolving-common-notarization-issues).
