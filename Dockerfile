# Multi-stage build: compile statically, ship a scratch-ish runtime.
FROM golang:1.25-alpine AS build
WORKDIR /src

# Cache deps before copying the rest.
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/gasoline .

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/gasoline /usr/local/bin/gasoline
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/gasoline"]
