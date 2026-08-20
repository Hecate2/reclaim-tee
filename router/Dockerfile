# Multi-stage build for the router service.
#
# Stage 1 builds a static binary against the full module (router imports
# shared/google_attestation.go and proto types, so we need the full repo).
# Stage 2 ships only the binary on `scratch`, matching the convention used
# by tee_k and tee_t in this repo. CA roots are copied from the builder so
# HTTPS to Google's JWKS endpoint works.
#
# Note: we deliberately do NOT use the `enclave` build tag here — the router
# is a normal Cloud Run service, not Confidential Space code.

# Go 1.27.0 -- keep this digest in sync with tee_k/tee_t Dockerfiles.
FROM golang:1.27.0-alpine3.24@sha256:c0ef102fd47cc7cfb3db3e93c4830f500307e37dad1dca44a3795e783cb0bf58 AS app-builder
ENV CGO_ENABLED=0
WORKDIR /src

# Pre-fetch modules in a separate layer so source edits don't bust the cache.
COPY --chown=0:0 go.mod go.sum ./
RUN go mod download

COPY --chown=0:0 . .

# osusergo + netgo keep user/DNS lookups in pure Go so the binary works on
# `scratch` (no /etc/passwd, no libc resolver).
# -trimpath + -s -w -buildid= produce a smaller, reproducible-ish binary.
RUN go build \
    -trimpath \
    -ldflags '-s -w -buildid= -extldflags=-static' \
    -tags 'osusergo netgo' \
    -o /out/router ./router

FROM scratch

# CA roots for HTTPS (Google JWKS fetcher).
COPY --chown=0:0 --from=app-builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

COPY --chown=0:0 --from=app-builder /out/router /router

EXPOSE 8080
ENTRYPOINT ["/router"]
