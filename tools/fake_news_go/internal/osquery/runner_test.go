package osquery

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestCommandRunnerRunDecodesJSON(t *testing.T) {
	t.Parallel()

	exec := &fakeExecutor{
		output: []byte(`[{"name":"uptime","seconds":"123"}]`),
	}

	runner := NewCommandRunner("osqueryi", exec)

	rows, err := runner.Run(context.Background(), "select * from uptime;")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(rows))
	}
	if rows[0]["name"] != "uptime" {
		t.Fatalf("unexpected row data: %+v", rows[0])
	}
	if exec.name != "osqueryi" {
		t.Fatalf("expected binary osqueryi, got %q", exec.name)
	}
	if len(exec.args) != 2 || exec.args[0] != "--json" || exec.args[1] != "select * from uptime;" {
		t.Fatalf("unexpected args: %#v", exec.args)
	}
}

func TestCommandRunnerRunPropagatesExecutorError(t *testing.T) {
	t.Parallel()

	runner := NewCommandRunner("osqueryi", &fakeExecutor{err: errors.New("boom")})

	if _, err := runner.Run(context.Background(), "select 1;"); err == nil {
		t.Fatal("expected executor error")
	}
}

func TestNewDefaultReturnsDeterministicSyntheticRows(t *testing.T) {
	t.Parallel()

	runner := NewDefault("ignored")

	first, err := runner.Run(context.Background(), "select * from uptime;")
	if err != nil {
		t.Fatalf("unexpected error on first run: %v", err)
	}
	second, err := runner.Run(context.Background(), "select * from uptime;")
	if err != nil {
		t.Fatalf("unexpected error on second run: %v", err)
	}
	if len(first) == 0 {
		t.Fatal("expected at least one synthetic row")
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("expected deterministic results, got first=%+v second=%+v", first, second)
	}
}

func TestNewDefaultReturnsFallbackRowsForUnknownQueries(t *testing.T) {
	t.Parallel()

	runner := NewDefault("ignored")

	rows, err := runner.Run(context.Background(), "select mysterious_field from custom_table;")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("expected one fallback row, got %d", len(rows))
	}
	if rows[0]["query"] == "" {
		t.Fatalf("expected fallback row to preserve query context, got %+v", rows[0])
	}
}

type fakeExecutor struct {
	name   string
	args   []string
	output []byte
	err    error
}

func (f *fakeExecutor) Output(_ context.Context, name string, args ...string) ([]byte, error) {
	f.name = name
	f.args = append([]string(nil), args...)
	return f.output, f.err
}
