# syntax=docker/dockerfile:1.6
# Build stage
FROM --platform=$BUILDPLATFORM golang:1.23.5-alpine AS build
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w" -o /out/server ./cmd/server

# Runtime stage
FROM --platform=$TARGETPLATFORM gcr.io/distroless/base-debian12:nonroot
WORKDIR /srv
COPY --from=build /out/server /srv/server
EXPOSE 8080
USER nonroot:nonroot
ENV GODEBUG=http2server=0
ENTRYPOINT ["/srv/server"]
