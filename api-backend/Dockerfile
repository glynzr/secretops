FROM golang:1.21-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev

WORKDIR /app
COPY go.mod ./
RUN go mod download || true

COPY . .
RUN go mod tidy && CGO_ENABLED=1 GOOS=linux go build -o secretops-api ./cmd/main.go

# ── Runtime ──────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates sqlite-libs tzdata wget

WORKDIR /app
COPY --from=builder /app/secretops-api .

RUN mkdir -p /data /tmp/repos

EXPOSE 8080
CMD ["./secretops-api"]
