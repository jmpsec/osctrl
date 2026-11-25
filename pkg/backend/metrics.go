package backend

import (
	"github.com/prometheus/client_golang/prometheus"
	"gorm.io/gorm"
)

var (
	dbPoolOpenDesc = prometheus.NewDesc(
		"osctrl_db_pool_open_connections",
		"Open database connections in the pool.",
		[]string{"role"}, nil)
	dbPoolInUseDesc = prometheus.NewDesc(
		"osctrl_db_pool_in_use_connections",
		"In-use database connections in the pool.",
		[]string{"role"}, nil)
	dbPoolIdleDesc = prometheus.NewDesc(
		"osctrl_db_pool_idle_connections",
		"Idle database connections in the pool.",
		[]string{"role"}, nil)
	dbPoolMaxOpenDesc = prometheus.NewDesc(
		"osctrl_db_pool_max_open_connections",
		"Maximum open database connections allowed by the pool.",
		[]string{"role"}, nil)
	dbPoolWaitCountDesc = prometheus.NewDesc(
		"osctrl_db_pool_wait_count_total",
		"Total number of times a caller waited for a database connection.",
		[]string{"role"}, nil)
	dbPoolWaitDurationDesc = prometheus.NewDesc(
		"osctrl_db_pool_wait_duration_seconds_total",
		"Total time spent waiting for a database connection.",
		[]string{"role"}, nil)
)

type dbPoolCollector struct {
	db *DBManager
}

// RegisterDBPoolMetrics exposes primary and read-replica SQL pool statistics.
// The collector reads sql.DB.Stats at scrape time, so it adds no hot-path cost.
func RegisterDBPoolMetrics(reg prometheus.Registerer, db *DBManager) {
	if reg == nil || db == nil {
		return
	}
	reg.MustRegister(&dbPoolCollector{db: db})
}

func (c *dbPoolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- dbPoolOpenDesc
	ch <- dbPoolInUseDesc
	ch <- dbPoolIdleDesc
	ch <- dbPoolMaxOpenDesc
	ch <- dbPoolWaitCountDesc
	ch <- dbPoolWaitDurationDesc
}

func (c *dbPoolCollector) Collect(ch chan<- prometheus.Metric) {
	if c.db == nil {
		return
	}
	pools := []struct {
		role string
		conn *gorm.DB
	}{{role: "primary", conn: c.db.Conn}}
	if c.db.Read != nil && c.db.Read != c.db.Conn {
		pools = append(pools, struct {
			role string
			conn *gorm.DB
		}{role: "read", conn: c.db.Read})
	}
	for _, pool := range pools {
		if pool.conn == nil {
			continue
		}
		sqlDB, err := pool.conn.DB()
		if err != nil {
			continue
		}
		stats := sqlDB.Stats()
		ch <- prometheus.MustNewConstMetric(dbPoolOpenDesc, prometheus.GaugeValue, float64(stats.OpenConnections), pool.role)
		ch <- prometheus.MustNewConstMetric(dbPoolInUseDesc, prometheus.GaugeValue, float64(stats.InUse), pool.role)
		ch <- prometheus.MustNewConstMetric(dbPoolIdleDesc, prometheus.GaugeValue, float64(stats.Idle), pool.role)
		ch <- prometheus.MustNewConstMetric(dbPoolMaxOpenDesc, prometheus.GaugeValue, float64(stats.MaxOpenConnections), pool.role)
		ch <- prometheus.MustNewConstMetric(dbPoolWaitCountDesc, prometheus.CounterValue, float64(stats.WaitCount), pool.role)
		ch <- prometheus.MustNewConstMetric(dbPoolWaitDurationDesc, prometheus.CounterValue, stats.WaitDuration.Seconds(), pool.role)
	}
}
