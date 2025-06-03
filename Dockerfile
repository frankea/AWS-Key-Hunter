FROM golang:1.22.0-alpine AS builder
ENV APP_DIR=/app
WORKDIR $APP_DIR
COPY go.mod go.sum ./
RUN go mod download
COPY . .
COPY .env .env
RUN go build -ldflags="-s -w" -o aws-key-scanner cmd/awskeyhunter/main.go

FROM gcr.io/distroless/static:nonroot
USER nonroot:nonroot
WORKDIR /app
COPY --from=builder /app/aws-key-scanner .
COPY --from=builder /app/.env .
ENTRYPOINT ["/app/aws-key-scanner"]
