# syntax=docker/dockerfile:1
ARG DISTRO=alpine:3.22
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
RUN CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -trimpath -ldflags='-s -w' -o /out/sbom-probe ./cmd/sbom-probe

FROM ghcr.io/anchore/syft:v1.57.2@sha256:e97e20b6e6d1699c60296b66ab337941724f9bd06ac279d893eda89601fc4b2a AS syft

FROM ${DISTRO}
ARG LAB_PACKAGES=""
RUN set -eu; \
    if [ -n "$LAB_PACKAGES" ]; then \
      if command -v apk >/dev/null; then \
        apk add --no-cache $LAB_PACKAGES; \
      else \
        apt-get update; \
        apt-get install -y --no-install-recommends $LAB_PACKAGES; \
        rm -rf /var/lib/apt/lists/*; \
      fi; \
    fi
COPY --from=build /out/sbom-probe /usr/local/bin/sbom-probe
COPY --from=syft /syft /usr/local/bin/syft
ENTRYPOINT ["/usr/local/bin/sbom-probe"]
CMD ["run", "-config", "/etc/sbom/config.json", "-watch"]
