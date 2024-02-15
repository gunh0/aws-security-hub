# Default Go environment variables
GO := go

# Run the application with arguments (e.g., make run ec2.1)
run: tidy
	$(GO) run main.go $(filter-out $@,$(MAKECMDGOALS))

# Ignore additional make arguments
%:
	@:

# Go module tidy (cleanup dependencies)
tidy:
	$(GO) mod tidy

# Run the application
start:
	$(GO) run main.go

# Clean Go cache and temporary files
clean:
	$(GO) clean

# Format Go code
fmt:
	$(GO) fmt ./...

# Run unit tests
test:
	$(GO) test ./...

# Build the Go application
build:
	$(GO) build -o aws-security-hub .

# Help menu
help:
	@echo "Usage:"
	@echo "  make run        - Run the application (tidy, start)"
	@echo "  make tidy       - Clean up Go module dependencies"
	@echo "  make start      - Start the Go application"
	@echo "  make clean      - Clean the Go build cache"
	@echo "  make fmt        - Format Go source code"
	@echo "  make test       - Run unit tests"
	@echo "  make build      - Build the application"
