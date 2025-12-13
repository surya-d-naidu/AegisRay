.PHONY: build clean proto server client mesh install deps

# Build all components
build: proto
	@echo "Building AegisRay..."
	go build -o bin/aegisray-server cmd/server/main.go
	go build -o bin/aegisray-client cmd/client/main.go
	go build -o bin/aegisray-mesh cmd/mesh/main.go
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
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/mesh/mesh.proto

# Build server only
server: proto
	go build -o bin/aegisray-server cmd/server/main.go

# Build client only
client: proto
	go build -o bin/aegisray-client cmd/client/main.go

# Build mesh node only
mesh: proto
	go build -o bin/aegisray-mesh cmd/mesh/main.go

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

# Run mesh node
run-mesh:
	sudo ./bin/aegisray-mesh -config=configs/mesh.yaml

# Run mesh exit node
run-exit-node:
	sudo ./bin/aegisray-mesh -config=configs/mesh-exit-node.yaml -exit-node

# Help
help:
	@echo "Available commands:"
	@echo "  build         - Build all components (server, client, mesh)"
	@echo "  server        - Build server only"
	@echo "  client        - Build client only"
	@echo "  mesh          - Build mesh node only"
	@echo "  proto         - Generate protobuf files"
	@echo "  deps          - Install Go dependencies"
	@echo "  setup         - Setup development environment"
	@echo "  clean         - Clean build artifacts"
	@echo "  run-server    - Run server (requires sudo)"
	@echo "  run-client    - Run client (requires sudo)"
	@echo "  run-mesh      - Run mesh node (requires sudo)"
	@echo "  run-exit-node - Run mesh exit node (requires sudo)"
	@echo "  help          - Show this help"
