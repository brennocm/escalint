# Multi-stage build from source: web UI (Node), binary with the UI embedded
# (Go), distroless nonroot runtime. Releases use Dockerfile.goreleaser, which
# copies the binaries GoReleaser already built.
#
#   docker build -t escalint .
#   docker run --rm -v "$PWD:/work" escalint scan /work/snapshot.json

# node:24-bookworm-slim
FROM node:24-bookworm-slim@sha256:55fb5f5a527ea2c5c4a95f963e48ef90aa38c7b346054fdc8ee9957a2b55d205 AS web
WORKDIR /src/web
RUN corepack enable
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
# Builds web/dist (served UI) and web/dist/report (single-file HTML report).
RUN pnpm build

# golang:1.27.3-bookworm
FROM golang:1.27.3-bookworm@sha256:972b4110ba0f47539a975c31e52c64765e1ff19f2d74469ae4a595c6676e80a5 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY --from=web /src/web/dist ./web/dist
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/brennocm/escalint/internal/buildinfo.Version=${VERSION} -X github.com/brennocm/escalint/internal/buildinfo.Commit=${COMMIT} -X github.com/brennocm/escalint/internal/buildinfo.Date=${DATE}" \
      -o /out/escalint ./cmd/escalint

# gcr.io/distroless/static-debian12:nonroot
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/escalint /usr/bin/escalint
WORKDIR /work
USER nonroot:nonroot
ENTRYPOINT ["/usr/bin/escalint"]
CMD ["--help"]
