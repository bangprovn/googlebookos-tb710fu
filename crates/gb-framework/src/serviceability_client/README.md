# Tips serviceability client

This builder replaces the eager service-binding constructor in one supported
serviceability JAR with lazy binding for `com.google.android.desktop.tips`.
Other callers keep the original constructor. The signed Tips APK is unchanged.

The first operation must run off the main thread. Connection acquisition has a
shared 1000 ms budget; synchronous Binder calls retain their original behavior.
Results come from the original services. Missing VPD or an unsupported backend
still fails, and this patch does not enable Perks eligibility.

## Build and test

```sh
cargo run --locked -p gb-framework --example serviceability_client -- REQUEST.json NEW_OUTPUT
PYTHONDONTWRITEBYTECODE=1 python3 crates/gb-framework/src/serviceability_client/host_tests.py
cargo test --locked -p gb-framework --example serviceability_client
```

The request specifies the original JAR, Android SDK/JDK tools, R8, JADX and a
sandbox image, all with input hashes. The builder parses the DEX offline,
checks that only the supported constructor changed, and verifies that removing
the insertion restores the original canonical DEX. Revert an assembled image
by restoring its original JAR. No firmware or patched JAR is bundled here.
