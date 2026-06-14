package runner

import "context"

func (r *SteadyRunner) Run(ctx context.Context) error {
	if r == nil {
		return nil
	}

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
