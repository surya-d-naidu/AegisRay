.PHONY: build clean proto mesh trustctl validate-smoke install-proto deps setup test run-mesh run-exit-node help

# Build all components
build: proto
	@echo "Building AegisRay..."
	go build -o bin/aegisray-mesh cmd/mesh/main.go
	go build -o bin/aegisray-trust cmd/trust/main.go
	@echo "Build complete. Binary in bin/"

# Install dependencies
deps:
	@echo "Installing dependencies..."
	go mod tidy
	go mod download

# Generate protobuf files
proto:
	@echo "Generating protobuf files..."
	export PATH=$(PATH):$(HOME)/go/bin && \
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/mesh/mesh.proto

# Build mesh node only
mesh: proto
	go build -o bin/aegisray-mesh cmd/mesh/main.go

trustctl:
	go build -o bin/aegisray-trust cmd/trust/main.go

validate-smoke:
	python3 scripts/validate_mesh_deployment.py \
		--compose-file docker-compose.test.yml \
		--startup \
		--teardown \
		--timeout 120 \
		--service mesh-node-1:1:8080 \
		--service mesh-node-2:1:8080

# Install protoc plugins
install-proto:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Setup development environment
setup: install-proto deps
	@echo "Creating bin directory..."
	mkdir -p bin
	@echo "Setup complete!"

# Run tests
test:
	GOCACHE=/tmp/aegisray-gocache go test ./...

# Clean build artifacts
clean:
	rm -rf bin/
	go clean

# Run mesh node
run-mesh:
	sudo ./bin/aegisray-mesh -config=configs/mesh.yaml

# Run mesh exit node
run-exit-node:
	sudo ./bin/aegisray-mesh -config=configs/mesh-exit-node.yaml -exit-node

# Help
help:
	@echo "Available commands:"
	@echo "  build         - Build the mesh binary"
	@echo "  mesh          - Build mesh node only"
	@echo "  trustctl      - Build trust bundle tooling"
	@echo "  validate-smoke - Run docker-compose smoke validation"
	@echo "  proto         - Generate protobuf files"
	@echo "  deps          - Install Go dependencies"
	@echo "  setup         - Setup development environment"
	@echo "  test          - Run Go tests with a writable cache"
	@echo "  clean         - Clean build artifacts"
	@echo "  run-mesh      - Run mesh node (requires sudo)"
	@echo "  run-exit-node - Run mesh exit node (requires sudo)"
	@echo "  help          - Show this help"
