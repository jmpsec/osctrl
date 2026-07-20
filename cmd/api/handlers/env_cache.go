package handlers

import (
	"context"

	"github.com/rs/zerolog/log"
)

func (h *HandlersApi) invalidateEnvCache(ctx context.Context, uuid string) {
	if h.EnvCache == nil || uuid == "" {
		return
	}
	h.EnvCache.InvalidateEnv(ctx, uuid)
	log.Debug().Str("env", uuid).Msg("invalidated environment cache")
}
