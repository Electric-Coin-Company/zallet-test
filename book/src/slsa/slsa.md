# Supply Chain Security (SLSA)

Zallet’s release automation is designed to satisfy the latest [SLSA v1.0](https://slsa.dev/spec/v1.0) “Build L3” expectations: every artifact is produced on GitHub Actions with an auditable workflow identity, emits a provenance statement, and is reproducible thanks to the [StageX](https://codeberg.org/stagex/stagex/) deterministic toolchain already integrated into this repository. This page documents how the workflows operate and provides the exact commands required to validate the resulting images, binaries, attestations, and repository metadata.

## Release architecture overview

### Workflows triggered on a `vX.Y.Z` tag

- **`.github/workflows/release.yml`** orchestrates the full release. It computes metadata (`set_env`), builds the StageX-based image (`container` job), and then fan-outs to the binaries-and-Debian job (`binaries_release`) before publishing all deliverables on the tagged GitHub Release.
- **`.github/workflows/build-and-push-docker-hub.yaml`** builds the OCI image deterministically, exports runtime artifacts per platform, pushes to Docker Hub, signs the digest with Cosign (keyless OIDC), uploads the SBOM, and generates provenance via `actions/attest-build-provenance`.
- **`.github/workflows/binaries-and-deb-release.yml`** consumes the exported binaries, performs smoke tests inside Debian containers, emits standalone binaries plus `.deb` packages, GPG-signs everything with the Zcash release key (decrypted from Google Cloud KMS), generates SPDX SBOMs, and attaches `intoto.jsonl` attestations for both the standalone binary and the `.deb`.
- **StageX deterministic build** is invoked before these workflows through `make build`/`utils/build.sh`. The Dockerfile’s `export` stage emits the exact binaries consumed later, guaranteeing that the images, standalone binaries, and Debian packages share the same reproducible artifacts.

### Deliverables and metadata per release

| Artifact | Where it ships | Integrity evidence |
| --- | --- | --- |
| Multi-arch OCI image (`docker.io/<namespace>/zallet-test`) | Docker Hub | Cosign signature, Rekor entry, auto-pushed SLSA provenance, SBOM |
| Exported runtime bundle | GitHub Actions artifact (`zallet-runtime-oci-*`) | Detached from release, referenced for auditing |
| Standalone binaries (`zallet-${VERSION}-linux-{amd64,arm64}`) | GitHub Release assets | GPG `.asc`, SPDX SBOM, `intoto.jsonl` provenance |
| Debian packages (`zallet_${VERSION}_{amd64,arm64}.deb`) | GitHub Release assets + apt.z.cash | GPG `.asc`, SPDX SBOM, `intoto.jsonl` provenance |
| APT repository | apt.z.cash | APT `Release.gpg`, package `.asc`, cosigned source artifacts |

## Targeted SLSA guarantees

- **Builder identity:** GitHub Actions workflows run with `permissions: id-token: write`, enabling keyless Sigstore certificates bound to the workflow path (`https://github.com/zcash/zallet/.github/workflows/<workflow>.yml@refs/tags/vX.Y.Z`).
- **Provenance predicate:** `actions/attest-build-provenance@v3` emits [`https://slsa.dev/provenance/v1`](https://slsa.dev/provenance/v1) predicates for every OCI image, standalone binary, and `.deb`. Each predicate captures the git tag, commit SHA, Docker/StageX build arguments, and resolved platform list.
- **Reproducibility:** StageX already enforces deterministic builds with source-bootstrapped toolchains. Re-running `make build` in a clean tree produces bit-identical images whose digests match the published release digest.

## Verification playbook

The following sections cover every command required to validate a tagged release end-to-end (similar to [Argo CD’s signed release process](https://argo-cd.readthedocs.io/en/stable/operator-manual/signed-release-assets/), but tailored to the Zallet workflows and the SLSA v1.0 predicate).

### Tooling prerequisites

- `cosign` ≥ 2.1 (Sigstore verification + SBOM downloads)
- `rekor-cli` ≥ 1.2 (transparency log inspection)
- `crane` or `skopeo` (digest lookup)
- `oras` (optional SBOM pull)
- `slsa-verifier` ≥ 2.5
- `gh` CLI (or `curl`) for release assets
- `jq`, `coreutils` (`sha256sum`)
- `gnupg`, `gpgv`, and optionally `dpkg-sig`
- Docker 25+ with containerd snapshotter (matches the CI setup) for deterministic rebuilds

Example installation on Debian/Ubuntu:

```bash
sudo apt-get update && sudo apt-get install -y jq gnupg coreutils rekor-cli
go install github.com/sigstore/cosign/v2/cmd/cosign@latest
go install github.com/google/go-containerregistry/cmd/crane@latest
go install github.com/slsa-framework/slsa-verifier/v2/cmd/slsa-verifier@latest
```

### Environment bootstrap

```bash
export VERSION=v1.2.3
export REPO=zcash/zallet
export IMAGE=docker.io/<namespace>/zallet-test               # replace <namespace> with the Docker Hub org stored in DOCKERHUB_REGISTRY
export IMAGE_WORKFLOW="https://github.com/${REPO}/.github/workflows/build-and-push-docker-hub.yaml@refs/tags/${VERSION}"
export BIN_WORKFLOW="https://github.com/${REPO}/.github/workflows/binaries-and-deb-release.yml@refs/tags/${VERSION}"
export OIDC_ISSUER="https://token.actions.githubusercontent.com"
mkdir -p verify/dist
```

### 1. Validate the git tag

```bash
git fetch origin --tags
git checkout "${VERSION}"
git verify-tag "${VERSION}"
git rev-parse HEAD
```

Confirm that the commit printed by `git rev-parse` matches the `subject.digest.gitCommit` recorded in every provenance file (see section **6**).

### 2. Verify the OCI image pushed to Docker Hub

```bash
export IMAGE_DIGEST=$(crane digest "${IMAGE}:${VERSION}")
cosign verify \
  --certificate-identity "${IMAGE_WORKFLOW}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  --rekor-output verify/dist/image-rekor.json \
  "${IMAGE}@${IMAGE_DIGEST}"

cosign verify-attestation \
  --type slsaprovenance \
  --certificate-identity "${IMAGE_WORKFLOW}" \
  --certificate-oidc-issuer "${OIDC_ISSUER}" \
  "${IMAGE}@${IMAGE_DIGEST}"

cosign download attestation \
  --predicate-type slsaprovenance \
  "${IMAGE}@${IMAGE_DIGEST}" > verify/dist/zallet-${VERSION}-image.slsa.intoto.jsonl

cosign download sbom \
  "${IMAGE}@${IMAGE_DIGEST}" > verify/dist/zallet-${VERSION}-image.sbom.spdx.json
rekor-cli get --log-index "$(jq -r '.LogIndex' verify/dist/image-rekor.json)"
```

The downloaded SBOM is generated directly by the build (`sbom: true`). Inspect it with `jq` or `syft` to validate dependencies.

### 3. Verify standalone binaries exported from the StageX image

```bash
gh release download "${VERSION}" --repo "${REPO}" \
  --pattern "zallet-${VERSION}-linux-*" \
  --dir verify/dist

curl -sSf https://apt.z.cash/zcash.asc | gpg --import -
for arch in linux-amd64 linux-arm64; do
  gpg --verify "verify/dist/zallet-${VERSION}-${arch}.asc" "verify/dist/zallet-${VERSION}-${arch}"
  sha256sum "verify/dist/zallet-${VERSION}-${arch}" | tee "verify/dist/zallet-${VERSION}-${arch}.sha256"
  slsa-verifier verify-artifact \
    --provenance-path "verify/dist/zallet-${VERSION}-${arch}.intoto.jsonl" \
    --source-uri "github.com/${REPO}" \
    --source-tag "${VERSION}" \
    --builder-id "https://github.com/actions/attest-build-provenance@v1" \
    "verify/dist/zallet-${VERSION}-${arch}"
  jq -r '.subject[0].digest.sha256' "verify/dist/zallet-${VERSION}-${arch}.intoto.jsonl"
done
```

Ensure the SHA-256 printed by `jq` matches the `sha256sum` output. Examine the SPDX SBOM shipped next to each binary:

```bash
grep -F "PackageChecksum" "verify/dist/zallet-${VERSION}-linux-amd64.sbom.spdx"
```

### 4. Verify Debian packages before consumption or mirroring

```bash
gh release download "${VERSION}" --repo "${REPO}" \
  --pattern "zallet_${VERSION}_*.deb*" \
  --dir verify/dist

for arch in amd64 arm64; do
  gpg --verify "verify/dist/zallet_${VERSION}_${arch}.deb.asc" "verify/dist/zallet_${VERSION}_${arch}.deb"
  dpkg-deb --info "verify/dist/zallet_${VERSION}_${arch}.deb" | head
  slsa-verifier verify-artifact \
    --provenance-path "verify/dist/zallet_${VERSION}_${arch}.deb.intoto.jsonl" \
    --source-uri "github.com/${REPO}" \
    --source-tag "${VERSION}" \
    --builder-id "https://github.com/actions/attest-build-provenance@v1" \
    "verify/dist/zallet_${VERSION}_${arch}.deb"
  jq -r '.subject[0].digest.sha256' "verify/dist/zallet_${VERSION}_${arch}.deb.intoto.jsonl"
done
```

The `.deb` SBOM files (`.sbom.spdx`) capture package checksums; compare them with `sha256sum zallet_${VERSION}_${arch}.deb`.

### 5. Validate apt.z.cash metadata

```bash
curl -sSfO https://apt.z.cash/zcash.asc
gpg --no-default-keyring --keyring ./zcash-apt.gpg --import zcash.asc

for dist in bullseye bookworm; do
  curl -sSfO "https://apt.z.cash/dists/${dist}/Release"
  curl -sSfO "https://apt.z.cash/dists/${dist}/Release.gpg"
  gpgv --keyring ./zcash-apt.gpg "Release.gpg" "Release"
  grep -A3 zallet "Release"
done

apt-get update
apt-cache policy zallet
apt-get download zallet
gpg --verify zallet_*_*.deb.asc zallet_*_*.deb
```

This ensures the repository metadata and package signatures match the GPG key decrypted inside the `binaries-and-deb-release` workflow.

### 6. Inspect provenance predicates (SLSA v1.0)

For any provenance file downloaded above:

```bash
FILE=verify/dist/zallet-${VERSION}-image.slsa.intoto.jsonl
jq -r '.predicate.builder.id' "${FILE}"
jq -r '.predicate.buildDefinition.externalParameters.version' "${FILE}"
jq -r '.predicate.materials[] | select(.uri | test(".git$")) | .digest.sha1' "${FILE}"
```

Cross-check that:

- `builder.id` equals `https://github.com/actions/attest-build-provenance@v3`.
- `subject[].digest.sha256` matches the artifact’s `sha256sum`.
- `materials[].digest.sha1` equals the `git rev-parse` result from Step 1.

Automated validation:

```bash
slsa-verifier verify-attestation \
  --provenance-path "${FILE}" \
  --source-uri "github.com/${REPO}" \
  --source-tag "${VERSION}" \
  --builder-id "https://github.com/actions/attest-build-provenance@v1"
```

### 7. Reproduce the deterministic StageX build locally

```bash
git clean -fdx
git checkout "${VERSION}"
make build IMAGE_TAG="${VERSION}"
skopeo inspect docker-archive:build/oci/zallet.tar | jq -r '.Digest'
```

Compare the digest returned by `skopeo` (or `docker image inspect`) with `${IMAGE_DIGEST}` from Step 2. Because StageX enforces hermetic toolchains (`utils/build.sh`), the digests must match bit-for-bit. After importing:

```bash
make import IMAGE_TAG="${VERSION}"
docker run --rm zallet:${VERSION} zallet --version
```

Running this reproduction as part of downstream promotion pipelines provides additional assurance that the published image and binaries stem from the deterministic StageX build.

## Residual work

- Extend the attestation surface (e.g., SBOM attestations, vulnerability scans) if higher SLSA levels or in-toto policies are desired downstream.
