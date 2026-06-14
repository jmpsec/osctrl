package osquery

import (
	"context"
	"encoding/json"
	"os/exec"
	"strings"
)

const defaultBinary = "osqueryi"

type Executor interface {
	Output(ctx context.Context, name string, args ...string) ([]byte, error)
}

type Runner struct {
	binary   string
	executor Executor
}

func New(binary string, executor Executor) *Runner {
	if strings.TrimSpace(binary) == "" {
		binary = defaultBinary
	}
	if executor == nil {
		executor = execExecutor{}
	}

	return &Runner{
		binary:   binary,
		executor: executor,
	}
}

func NewDefault(binary string) *Runner {
	return &Runner{
		binary:   binary,
		executor: simulatorExecutor{},
	}
}

func NewCommandRunner(binary string, executor Executor) *Runner {
	return New(binary, executor)
}

func (r *Runner) Run(ctx context.Context, query string) ([]map[string]interface{}, error) {
	output, err := r.executor.Output(ctx, r.binary, "--json", query)
	if err != nil {
		return nil, err
	}

	var results []map[string]interface{}
	if err := json.Unmarshal(output, &results); err != nil {
		return nil, err
	}

	return results, nil
}

func (r *Runner) RunJSON(query string) ([]map[string]interface{}, error) {
	return r.Run(context.Background(), query)
}

type execExecutor struct{}

func (execExecutor) Output(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).Output()
}

type simulatorExecutor struct{}

func (simulatorExecutor) Output(_ context.Context, _ string, args ...string) ([]byte, error) {
	query := ""
	if len(args) > 1 {
		query = args[1]
	}
	return json.Marshal(simulateRows(query))
}

func simulateRows(query string) []map[string]interface{} {
	normalized := strings.ToLower(strings.TrimSpace(query))

	switch {
	case strings.Contains(normalized, "from uptime"):
		return []map[string]interface{}{
			{
				"days":          "4",
				"hours":         "12",
				"minutes":       "7",
				"seconds":       "33",
				"total_seconds": "389253",
			},
		}
	case strings.Contains(normalized, "osquery_info"):
		return []map[string]interface{}{
			{
				"name":    "osqueryd",
				"version": "5.23.0",
				"pid":     "4242",
			},
		}
	case strings.Contains(normalized, "system_info"):
		return []map[string]interface{}{
			{
				"hostname":    "fake-news-host",
				"cpu_brand":   "Intel(R) Core(TM) i7",
				"physical_mb": "8192",
			},
		}
	default:
		return []map[string]interface{}{
			{
				"query":  query,
				"status": "simulated",
			},
		}
	}
}
