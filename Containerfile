# Build stage
FROM golang:1.23.5-alpine AS build
WORKDIR /app
RUN apk add --no-cache ca-certificates tzdata
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "-s -w" -o /out/server ./cmd/server

# Runtime stage
FROM gcr.io/distroless/base-debian12:nonroot
WORKDIR /srv
COPY --from=build /out/server /srv/server
EXPOSE 8080
USER nonroot:nonroot
ENV GODEBUG=http2server=0
ENTRYPOINT ["/srv/server"]
