FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server

FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/server /app/server
ENV PORT=8080
ENV SERVICE_NAME=rac-user-service
EXPOSE 8080
ENTRYPOINT ["/app/server"]
