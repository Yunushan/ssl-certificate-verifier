FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/sslcertcheck ./cmd/sslcertcheck

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && adduser -D -H -s /sbin/nologin app
COPY --from=build /out/sslcertcheck /usr/local/bin/sslcertcheck
USER app
ENTRYPOINT ["sslcertcheck"]
CMD ["--help"]
