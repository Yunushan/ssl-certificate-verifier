APP := sslcertcheck
PKG := ./cmd/sslcertcheck

.PHONY: test build run gui clean

test:
	go test ./...

build:
	mkdir -p bin
	go build -trimpath -o bin/$(APP) $(PKG)

run: build
	./bin/$(APP) check example.com

gui: build
	./bin/$(APP) gui --open --listen 127.0.0.1:8088

clean:
	rm -rf bin dist coverage.out
