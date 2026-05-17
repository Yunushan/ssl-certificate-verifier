# Platform Notes

## Desktop and server platforms

The project is built with Go and uses only the Go standard library. The same command can be built for Windows, Windows Server, Linux, macOS, FreeBSD, OpenBSD, NetBSD and Solaris/illumos where Go supports the selected architecture.

The GUI is browser-based and served by the binary, which avoids native GUI toolkit differences across platforms.

## Android

Android support is available in two practical modes:

1. Run the CLI in a terminal environment such as Termux.
2. Run the GUI on any reachable checker host and open it from an Android browser.

Example build target:

```bash
GOOS=android GOARCH=arm64 go build -o dist/sslcertcheck-android-arm64 ./cmd/sslcertcheck
```

## iOS and iPadOS

iOS does not normally allow arbitrary local CLI binaries to run like desktop operating systems. Supported modes are:

1. Open the browser GUI from an iPhone/iPad against a checker host reachable on the network.
2. Embed the checker library in a signed native wrapper if your organization needs a dedicated iOS app.

## Solaris / illumos

Build with a Go toolchain that supports your Solaris/illumos architecture. The browser GUI and CLI do not rely on Linux-only APIs.
