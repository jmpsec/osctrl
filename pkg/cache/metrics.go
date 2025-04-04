package cache

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metric names and help text
const (
	cacheHitsName      = "osctrl_cache_hits_total"
	cacheHitsHelp      = "Total number of cache hits"
	cacheMissesName    = "osctrl_cache_misses_total"
	cacheMissesHelp    = "Total number of cache misses"
	cacheEvictionsName = "osctrl_cache_evictions_total"
	cacheEvictionsHelp = "Total number of cache evictions"
	cacheItemsName     = "osctrl_cache_items"
	cacheItemsHelp     = "Current number of items in cache"
)

var (
	// CacheHits tracks the number of cache hits
	CacheHits = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: cacheHitsName,
			Help: cacheHitsHelp,
		},
		[]string{"cache_name"},
	)

	// CacheMisses tracks the number of cache misses
	CacheMisses = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: cacheMissesName,
			Help: cacheMissesHelp,
		},
		[]string{"cache_name"},
	)

	// CacheEvictions tracks the number of cache evictions
	CacheEvictions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: cacheEvictionsName,
			Help: cacheEvictionsHelp,
		},
		[]string{"cache_name"},
	)

	// CacheItems tracks the current number of items in the cache
	CacheItems = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: cacheItemsName,
			Help: cacheItemsHelp,
		},
		[]string{"cache_name"},
	)
)

// RegisterMetrics registers all cache metrics with the provided registerer
func RegisterMetrics(reg prometheus.Registerer) {
	reg.MustRegister(CacheHits)
	reg.MustRegister(CacheMisses)
	reg.MustRegister(CacheEvictions)
	reg.MustRegister(CacheItems)
}
