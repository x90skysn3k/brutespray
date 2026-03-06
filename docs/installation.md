# Installation

## Go Install

Requires Go 1.21+:

```bash
go install github.com/x90skysn3k/brutespray/v2@latest
```

## Release Binaries

Pre-built binaries for Linux, macOS, and Windows are available on the [Releases page](https://github.com/x90skysn3k/brutespray/releases).

Download the archive for your platform, extract, and place the binary in your `$PATH`.

## Build from Source

```bash
git clone https://github.com/x90skysn3k/brutespray.git
cd brutespray
go build -o brutespray main.go
```

## Docker

```bash
docker build -t brutespray .
docker run brutespray -H ssh://target:22 -u admin -p password
```

The Docker image uses a multi-stage build with Alpine Linux and runs as a non-root user.

## Kali Linux

Brutespray is available in the Kali Linux repositories:

```bash
apt install brutespray
```

> **Note:** The repository version may lag behind the latest release. For the newest features, use `go install` or download a release binary.
