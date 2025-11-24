# Torgo

Torgo is a lightweight, multi-architecture (AMD64/ARM64) Go-based Tor multi-circuit orchestrator designed for secure, privacy-oriented network routing. It includes:

- Multi-arch Docker builds (linux/amd64, linux/arm64)
- Hardened scratch-based container runtime with minimal attack surface
- Tor binary + required dependencies bundled
- Automatic SBOM and SLSA provenance generation (GitHub Actions)
- Keyless Cosign signing + signature verification
- Digest-first publishing for zero-trust image integrity

---

## 🚀 Features

### **1. Multi-Arch Secure Docker Builds**
Torgo uses Docker Buildx to build fully static binaries with CGO enabled and Tor integration.

### **2. Scratch Runtime Image**
The final image is ~12-15 MB and includes only:
- statically compiled `torgo`
- Tor binary + required libraries
- musl loader
- torrc template

### **3. Zero-Trust Supply Chain**
Your container images are:
- SBOM-attested
- Provenance-attested
- Signed with Cosign keyless signing
- Verified inside CI
- Published digest-first, then tagged

### **4. Reproducible Builds**
All metadata (labels, tags) comes from GitHub’s `docker/metadata-action`.

---

## 📦 Installation

### Pull the latest verified image
```
docker pull ghcr.io/myhme/torgo:latest
```

### Or pull a signed digest
```
docker pull ghcr.io/myhme/torgo@sha256:<digest>
```

---

## 🔒 Verifying Signature with Cosign

Torgo images are **signed using Sigstore keyless**.

### Verify locally:
```
cosign verify ghcr.io/myhme/torgo:latest \
  --certificate-identity-regexp 'https://github.com/myhme/torgo/.github/workflows/docker-publish.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

Expected output includes:
```
Verified OK
```

---

## 🛠 Local Development

### Build locally using the provided Dockerfile
```
docker buildx build \
  --platform=linux/amd64 \
  -t torgo:dev .
```

### Run locally
```
docker run --rm -it torgo:dev
```

---

## 🏗 CI/CD Pipeline Overview

The repository includes a hardened GitHub Actions workflow:
- Multi-arch build
- Push by digest
- SBOM + provenance attestation
- Keyless Cosign signing
- Signature verification
- Cleanup of untagged images

All metadata (title, version, revision, created date) comes from:
```
docker/metadata-action@v5
```

---

## 📁 Project Structure

```
cmd/torgo/       → Command entrypoint
internal/        → Internal packages
torrc.template   → Tor runtime config
Dockerfile        → Multi-arch scratch build
.github/workflows → CI pipelines
```

---

## 🧩 Configuration

Torgo uses `torrc.template` which is loaded and modified at runtime.

To override:
```
docker run -v $(pwd)/torrc.template:/etc/tor/torrc.template ghcr.io/myhme/torgo:latest
```

---

## 🧪 Testing

### Run unit tests
```
go test ./...
```

---

## 📝 License

MIT License — see LICENSE file.

---

## ❤️ Contributing

PRs and issues are welcome. For major changes, please discuss them first via an issue.

---

## ⭐ Support

If you find Torgo useful, consider starring the repository.
