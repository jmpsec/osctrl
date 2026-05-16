package dbutil

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// BucketExpr returns the SQL expression that floors `created_at` to a
// bucket-aligned unix timestamp. Same shape on every dialect — only the
// epoch-extraction function differs.
//
// The expression returns an integer number of seconds since the epoch,
// truncated down to the nearest `bucketSeconds` boundary. Group by this
// expression, count(*), and you have a contiguous-bucket histogram.
func BucketExpr(db *gorm.DB, column string, bucketSeconds int) string {
	switch db.Dialector.Name() {
	case "postgres":
		return fmt.Sprintf(
			"(floor(extract(epoch from %s) / %d) * %d)::bigint",
			column, bucketSeconds, bucketSeconds,
		)
	case "mysql":
		return fmt.Sprintf(
			"(FLOOR(UNIX_TIMESTAMP(%s) / %d) * %d)",
			column, bucketSeconds, bucketSeconds,
		)
	case "sqlite":
		return fmt.Sprintf(
			"(CAST(strftime('%%s', %s) AS INTEGER) / %d * %d)",
			column, bucketSeconds, bucketSeconds,
		)
	default:
		// Best-effort SQL-92-ish fallback; not all dialects accept this but
		// the three supported dialects above are covered.
		return fmt.Sprintf(
			"(CAST(strftime('%%s', %s) AS INTEGER) / %d * %d)",
			column, bucketSeconds, bucketSeconds,
		)
	}
}

// BucketCount represents one row of a bucketed count query.
type BucketCount struct {
	Bucket int64 // Unix seconds at the start of the bucket
	Count  int64
}

// BucketedRow is the raw scan target for the GROUP BY query. Stays
// dialect-agnostic since every dialect returns BIGINT for FLOOR/CAST
// expressions.
type BucketedRow struct {
	BucketStart int64 `gorm:"column:bucket_start"`
	Cnt         int64 `gorm:"column:cnt"`
}

// DensifyBuckets takes a sparse list of {bucketStart, count} rows from the
// DB and emits a dense `nBuckets`-long slice aligned to `startUnix`. Bucket
// indexes outside the range are dropped — they can't render in a heatmap
// of fixed width.
func DensifyBuckets(rows []BucketedRow, startUnix int64, bucketSeconds int, nBuckets int) []int64 {
	out := make([]int64, nBuckets)
	for _, r := range rows {
		idx := int((r.BucketStart - startUnix) / int64(bucketSeconds))
		if idx < 0 || idx >= nBuckets {
			continue
		}
		out[idx] = r.Cnt
	}
	return out
}

// AlignBucketStart rounds `t` down to the nearest `bucketSeconds` boundary.
// Used so the API and the rollup-writer agree on bucket edges to the second.
func AlignBucketStart(t time.Time, bucketSeconds int) time.Time {
	return time.Unix((t.UTC().Unix()/int64(bucketSeconds))*int64(bucketSeconds), 0).UTC()
}
