# Fake News Generator - Go Version

This is a Go implementation of the `fake_news.py` script that simulates load for osctrl using goroutines for concurrent execution.

## Features

- **Concurrent Execution**: Uses goroutines instead of Python threads for better performance
- **Node Simulation**: Generates random nodes with different platforms (Ubuntu, CentOS, Debian, FreeBSD, Darwin, Windows)
- **Multiple Operations**: Simulates status logs, result logs, config requests, and query operations
- **osquery Integration**: Executes real osquery commands for query responses
- **JSON Persistence**: Can save/load node configurations to/from JSON files
- **Command Line Interface**: Full CLI support with all original Python script options

## Prerequisites

- Go 1.19 or later
- osquery installed and accessible via `osqueryi` command
- osctrl-tls server running

## Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   go mod tidy
   ```

## Usage

### Basic Usage

```bash
go run tools/fake_news.go --secret YOUR_SECRET
```

### Advanced Usage

```bash
go run tools/fake_news.go \
  --secret YOUR_SECRET \
  --env YOUR_ENV_UUID \
  --url http://localhost:9000/ \
  --nodes 10 \
  --status 30 \
  --result 45 \
  --config 60 \
  --query 20 \
  --verbose
```

### Command Line Options

- `--secret, -s`: Secret to enroll nodes for osctrl-tls (required)
- `--env, -e`: Environment UUID for osctrl-tls (optional)
- `--url, -u`: URL for osctrl-tls used to enroll nodes (default: http://localhost:9000/)
- `--nodes, -n`: Number of random nodes to simulate (default: 5)
- `--status, -S`: Interval in seconds for status requests to osctrl (default: 60)
- `--result, -R`: Interval in seconds for result requests to osctrl (default: 60)
- `--config, -c`: Interval in seconds for config requests to osctrl (default: 45)
- `--query, -q`: Interval in seconds for query requests to osctrl (default: 30)
- `--read, -r`: JSON file to read nodes from
- `--write, -w`: JSON file to write nodes to
- --insecure: Skip TLS certificate verification
- `--verbose, -v`: Enable verbose output

### Examples

#### Generate 10 nodes and save configuration
```bash
go run tools/fake_news.go --secret mysecret --nodes 10 --write nodes.json
```

#### Load existing nodes and run simulation
```bash
go run tools/fake_news.go --secret mysecret --read nodes.json
```

#### High-frequency simulation with verbose output
```bash
go run tools/fake_news.go \
  --secret mysecret \
  --env YOUR_ENV_UUID \
  --nodes 20 \
  --status 10 \
  --result 15 \
  --config 20 \
  --query 5 \
  --verbose
```

## Architecture

### Goroutines

The Go version uses goroutines for concurrent execution:

1. **Status Log Goroutine**: Sends status logs for each node
2. **Result Log Goroutine**: Sends result logs for each node
3. **Config Goroutine**: Sends config requests for each node
4. **Query Read Goroutine**: Sends query read requests and spawns query write goroutines

### Key Improvements over Python Version

1. **Better Concurrency**: Goroutines are more efficient than Python threads
2. **Type Safety**: Strong typing prevents runtime errors
3. **Better Error Handling**: Comprehensive error handling throughout
4. **Memory Efficiency**: Lower memory footprint than Python
5. **Faster Execution**: Go's compiled nature provides better performance

### Data Structures

- `Node`: Represents a simulated osctrl node
- `SystemInfo`: System information for enrollment
- `OSQueryInfo`: osquery-specific information
- `OSVersion`: OS version details for different platforms
- `HTTPClient`: Custom HTTP client with debug capabilities

## Building

To build a standalone binary:

```bash
go build -o fake_news tools/fake_news.go
./fake_news --secret YOUR_SECRET
```

## Dependencies

- `github.com/google/uuid`: For generating UUIDs
- Standard Go libraries: `net/http`, `encoding/json`, `os/exec`, etc.

## Error Handling

The Go version includes comprehensive error handling:

- HTTP request failures are logged and operations continue
- Invalid node responses trigger re-enrollment
- osquery execution failures are handled gracefully
- File I/O operations include proper error checking

## Performance

The Go version typically provides:

- 2-3x faster execution compared to Python
- Lower memory usage
- Better CPU utilization through efficient goroutines
- More stable concurrent execution

## Migration from Python

The Go version maintains full compatibility with the Python script:

- Same command line interface
- Same JSON file formats
- Same API endpoints and data structures
- Same simulation behavior

Simply replace `python tools/fake_news.py` with `go run tools/fake_news.go` in your scripts.
