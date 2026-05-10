# Multi-stage build: compile each binary statically, ship them all
# in a single distroless image. ENTRYPOINT is unset; pick which
# binary to run via CMD or `docker run <image> /usr/local/bin/<name>`.
FROM golang:1.25-alpine AS build
WORKDIR /src

# Cache deps before copying the rest.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN set -eux; \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/operator   ./cmd/operator; \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cordinator ./cmd/cordinator; \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gasoctl    ./cmd/gasoctl

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/operator   /usr/local/bin/operator
COPY --from=build /out/cordinator /usr/local/bin/cordinator
COPY --from=build /out/gasoctl    /usr/local/bin/gasoctl
USER nonroot:nonroot
# No ENTRYPOINT: explicit choice of binary at `docker run` time.
# Default to operator for convenience.
CMD ["/usr/local/bin/operator"]
