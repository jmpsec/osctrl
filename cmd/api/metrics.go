package main

import (
	"net/http"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog/log"

	"github.com/jmpsec/osctrl/pkg/cache"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/httpmetrics"
)

// startAPIMetrics registers the API's request metrics and starts the separate
// Prometheus listener. Keeping it on its own port lets operators expose metrics
// only on a private interface while the API listens on its normal address.
func startAPIMetrics(params *config.ServiceParameters) {
	httpmetrics.Register(prometheus.DefaultRegisterer)
	cache.RegisterMetrics(prometheus.DefaultRegisterer)

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.Handler())
	address := params.Metrics.Listener + ":" + strconv.Itoa(params.Metrics.Port)
	go func() {
		log.Info().Msgf("Starting prometheus server at %s", address)
		if err := http.ListenAndServe(address, metricsMux); err != nil {
			log.Fatal().Msgf("Error starting prometheus server: %v", err)
		}
	}()
}
