.PHONY: build clean proto server client install deps

# Build both client and server
build: proto
	@echo "Building AegisRay..."
	go build -o bin/aegisray-server cmd/server/main.go
	go build -o bin/aegisray-client cmd/client/main.go
	@echo "Build complete. Binaries in bin/"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod download

# Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/tunnel/tunnel.proto

# Build server only
server: proto
	go build -o bin/aegisray-server cmd/server/main.go

# Build client only
client: proto
	go build -o bin/aegisray-client cmd/client/main.go

# Install protoc plugins
install-proto:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Setup development environment
setup: install-proto deps
	@echo "Creating bin directory..."
	mkdir -p bin
	@echo "Setup complete!"

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

# Run server
run-server:
	sudo ./bin/aegisray-server -config=configs/server.yaml

# Run client
run-client:
	sudo ./bin/aegisray-client -config=configs/client.yaml

# Help
help:
	@echo "Available commands:"
	@echo "  build       - Build both client and server"
	@echo "  server      - Build server only"
	@echo "  client      - Build client only"
	@echo "  proto       - Generate protobuf files"
	@echo "  deps        - Install Go dependencies"
	@echo "  setup       - Setup development environment"
	@echo "  clean       - Clean build artifacts"
	@echo "  run-server  - Run server (requires sudo)"
	@echo "  run-client  - Run client (requires sudo)"
	@echo "  help        - Show this help"
