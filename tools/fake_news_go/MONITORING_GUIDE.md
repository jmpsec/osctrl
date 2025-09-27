# Enhanced Fake News Generator - Advanced Monitoring

This enhanced version of the fake_news.go script provides comprehensive monitoring capabilities for running thousands of nodes without overwhelming output. The improvements focus on latency monitoring, statistical analysis, and configurable output modes.

## 🚀 Key Monitoring Features

### 📊 **Advanced Latency Statistics**

- **Min/Max/Average latency** for each operation type
- **P95 and P99 percentiles** for performance analysis
- **Success/failure rates** with detailed counters
- **Real-time statistics** updated continuously

### 🎛️ **Multiple Output Modes**

#### 1. **Quiet Mode** (`--mode quiet`)

- No per-request output
- Minimal startup message only
- Perfect for background monitoring
- Ideal for thousands of nodes

#### 2. **Summary Mode** (`--mode summary`) - **Default**

- Periodic summary reports every 30 seconds (configurable)
- Comprehensive statistics table
- Shows all operation types with latency metrics
- Perfect balance of information and readability

#### 3. **Verbose Mode** (`--mode verbose`)

- Original per-request output with success/failure indicators
- Detailed error messages
- Best for debugging and development

#### 4. **Dashboard Mode** (`--mode dashboard`)

- Real-time updating dashboard
- Clears screen and refreshes every 2 seconds
- Live statistics with current timestamps
- Perfect for monitoring sessions

#### 5. **JSON Mode** (`--mode json`)

- Machine-readable JSON output
- Periodic JSON reports with all statistics
- Perfect for integration with monitoring systems
- Structured data for analysis tools

## 📈 **Statistical Tracking**

### Operation Types Monitored

- **Enroll**: Node enrollment operations
- **Status**: Status log submissions
- **Result**: Result log submissions
- **Config**: Configuration requests
- **Query Read**: Query read operations
- **Query Write**: Query write operations

### Metrics Per Operation

- **Count**: Total number of operations
- **Success Rate**: Percentage of successful operations
- **Min Latency**: Fastest operation time
- **Average Latency**: Mean operation time
- **Max Latency**: Slowest operation time
- **P95 Latency**: 95th percentile latency
- **P99 Latency**: 99th percentile latency

## 🛠️ **Usage Examples**

### High-Scale Monitoring (Recommended for Thousands of Nodes)

```shell
# Quiet mode - minimal output, maximum performance
go run tools/fake_news_go/fake_news.go \
  --secret YOUR_SECRET \
  --nodes 5000 \
  --mode quiet

# Summary mode - periodic reports every 60 seconds
go run tools/fake_news_go/fake_news.go \
  --secret YOUR_SECRET \
  --nodes 2000 \
  --mode summary \
  --summary-interval 60

# Dashboard mode - real-time monitoring
go run tools/fake_news_go/fake_news.go \
  --secret YOUR_SECRET \
  --nodes 1000 \
  --mode dashboard
```

### Integration with Monitoring Systems

```shell
# JSON output for log aggregation
go run tools/fake_news_go/fake_news.go \
  --secret YOUR_SECRET \
  --nodes 1000 \
  --mode json \
  --summary-interval 30 | \
  jq '.operations.status.avg_ms'

# Pipe to monitoring tools
go run tools/fake_news_go/fake_news.go \
  --secret YOUR_SECRET \
  --nodes 5000 \
  --mode json | \
  tee /var/log/osctrl-metrics.json
```

### Development and Debugging

```shell
# Verbose mode for detailed debugging
go run tools/fake_news_go/fake_news.go \
  --secret YOUR_SECRET \
  --nodes 10 \
  --mode verbose \
  --status 5 \
  --result 5 \
  --config 10 \
  --query 5
```

## 📋 **Command Line Options**

### New Monitoring Options

- `--mode`: Output mode (quiet, summary, verbose, dashboard, json)
- `--summary-interval`: Interval in seconds for summary reports (default: 30)

### Existing Options (Enhanced)

- `--secret, -s`: Secret to enroll nodes (required)
- `--url, -u`: osctrl-tls URL (default: http://localhost:9000/)
- `--nodes, -n`: Number of nodes to simulate (default: 5)
- `--status, -S`: Status request interval in seconds (default: 60)
- `--result, -R`: Result request interval in seconds (default: 60)
- `--config, -c`: Config request interval in seconds (default: 45)
- `--query, -q`: Query request interval in seconds (default: 30)
- `--verbose, -v`: Force verbose mode (overrides --mode)

## 📊 **Sample Output**

### Summary Mode Output

```shell
================================================================================
FAKE NEWS GENERATOR - PERFORMANCE SUMMARY
Uptime: 2m30s
================================================================================
Enroll      | Count:     50 | Success:  98.0% | Min:   45ms | Avg:   78ms | Max:  156ms | P95:  134ms | P99:  145ms
Status      | Count:   1250 | Success:  99.2% | Min:   12ms | Avg:   23ms | Max:   89ms | P95:   45ms | P99:   67ms
Result      | Count:   1250 | Success:  99.1% | Min:   15ms | Avg:   28ms | Max:   95ms | P95:   52ms | P99:   78ms
Config      | Count:    833 | Success:  98.8% | Min:   18ms | Avg:   31ms | Max:  102ms | P95:   58ms | P99:   85ms
Query Read  | Count:   1667 | Success:  97.9% | Min:   22ms | Avg:   35ms | Max:  125ms | P95:   67ms | P99:   98ms
Query Write | Count:    234 | Success:  96.6% | Min:   45ms | Avg:   89ms | Max:  234ms | P95:  156ms | P99:  198ms
================================================================================
```

### JSON Mode Output

```json
{
  "uptime_seconds": 150.5,
  "timestamp": 1703123456,
  "operations": {
    "status": {
      "count": 1250,
      "success_count": 1240,
      "fail_count": 10,
      "success_rate": 99.2,
      "min_ms": 12,
      "avg_ms": 23,
      "max_ms": 89,
      "p95_ms": 45,
      "p99_ms": 67
    }
  }
}
```

## 🎯 **Performance Benefits**

### For Large-Scale Deployments

- **Reduced I/O**: Quiet mode eliminates per-request logging
- **Efficient Statistics**: Rolling window of last 1000 measurements
- **Memory Optimized**: Thread-safe statistics with minimal overhead
- **CPU Efficient**: Configurable reporting intervals

### Monitoring Capabilities

- **Real-time Insights**: Dashboard mode for live monitoring
- **Historical Analysis**: P95/P99 percentiles for performance trends
- **Integration Ready**: JSON output for external monitoring tools
- **Scalable**: Tested with thousands of concurrent nodes

## 🔧 **Technical Implementation**

### Statistics Engine

- **Thread-safe**: Uses mutexes for concurrent access
- **Memory Efficient**: Maintains rolling window of measurements
- **High Performance**: Minimal overhead per operation
- **Accurate Percentiles**: Proper sorting and calculation

### Output Modes

- **Configurable**: Easy to switch between modes
- **Non-blocking**: Monitoring doesn't affect performance
- **Flexible**: Customizable reporting intervals
- **Extensible**: Easy to add new output formats

## 🚀 **Best Practices**

### For Production Load Testing

1. **Start with Quiet Mode**: `--mode quiet` for maximum performance
2. **Use Summary Mode**: `--mode summary --summary-interval 60` for periodic insights
3. **Monitor P99 Latency**: Focus on 99th percentile for worst-case performance
4. **Track Success Rates**: Ensure >95% success rate for all operations

### For Development

1. **Use Verbose Mode**: `--mode verbose` for detailed debugging
2. **Lower Intervals**: Use faster intervals for quick testing
3. **Dashboard Mode**: `--mode dashboard` for real-time development monitoring

### For Integration

1. **JSON Output**: `--mode json` for monitoring system integration
2. **Structured Logging**: Pipe output to log aggregation systems
3. **Custom Intervals**: Adjust `--summary-interval` based on monitoring needs

This enhanced monitoring system provides the perfect balance between performance and observability, making it ideal for testing osctrl with thousands of nodes while maintaining detailed performance insights.
