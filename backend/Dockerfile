FROM golang:1.21-alpine AS builder
RUN apk add --no-cache gcc musl-dev git
WORKDIR /app
COPY go.mod ./
RUN go mod download || true
COPY . .
RUN go mod tidy
RUN CGO_ENABLED=1 GOOS=linux go build -o secretops-api ./cmd/main.go

FROM alpine:3.19
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/secretops-api .
RUN mkdir -p /app/data
EXPOSE 8080
CMD ["./secretops-api"]
