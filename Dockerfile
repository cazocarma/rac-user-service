FROM golang:1.27.2-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
COPY vendor ./vendor
ENV GOPROXY=off GOSUMDB=off
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o server ./cmd/server && CGO_ENABLED=0 GOOS=linux go build -o migrate-photos ./cmd/migrate-photos && CGO_ENABLED=0 GOOS=linux go build -o standing-sessions ./cmd/standing-sessions

FROM alpine:3.22
RUN addgroup -S rac && adduser -S -G rac rac && mkdir -p /var/lib/rac/photos && chown -R rac:rac /var/lib/rac
WORKDIR /app
COPY --from=builder /app/server /app/server
COPY --from=builder /app/migrate-photos /app/migrate-photos
COPY --from=builder /app/standing-sessions /app/standing-sessions
ENV PORT=8080
ENV SERVICE_NAME=rac-user-service
EXPOSE 8080
USER rac
ENTRYPOINT ["/app/server"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=15s CMD wget -q -O /dev/null http://127.0.0.1:8080/ready || exit 1
