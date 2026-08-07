package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/rs/zerolog/log"
)

// s3LogReader implements LogReader over S3 objects written by LoggerS3.
//
// Key layouts (must match the write path in s3.go):
//
//	status/result: {env}/{logType}/{uuid}:{ts}.json
//	query:        {env}/query/{name}/{uuid}:{ts}.json
//
// The timestamp in the key is millisecond Unix time, so lexical ordering
// of keys within a prefix == chronological ordering. ListObjectsV2 returns
// keys in lexical order, so the reader gets pre-sorted results for free
// and only needs to fetch the objects for the requested page/limit.
//
// Status/result reads list by prefix {env}/{logType}/ and keep only keys
// whose UUID segment matches (the prefix is environment-scoped, not
// node-scoped, because the write path does not nest under the node).
// Query reads list by prefix {env}/query/{name}/ which is already
// name-scoped, so every key in the prefix is a result for that query.
type s3LogReader struct {
	client *s3.Client
	bucket string
}

// NewS3LogReader returns a LogReader backed by the given S3 client/bucket.
// The client is the same one LoggerS3 already constructs at TLS startup,
// so the reader shares the configured credentials/region.
func NewS3LogReader(client *s3.Client, bucket string) LogReader {
	return &s3LogReader{client: client, bucket: bucket}
}

// NodeLogs implements LogReader. It lists the {env}/{logType}/ prefix,
// keeps keys whose UUID matches, applies the since/search filters
// (best-effort — the search is applied against the decoded JSON body),
// and returns up to `limit` rows ordered newest-first.
func (r *s3LogReader) NodeLogs(logType, env, uuid string, since time.Time, limit int, search string) ([]map[string]any, error) {
	prefix, err := normalizeLogType(logType)
	if err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	wantUUID := upperUUID(uuid)
	prefix = env + "/" + prefix + "/"

	keys, err := r.listKeys(prefix)
	if err != nil {
		return nil, err
	}
	// Keys are returned lexically (oldest first). We want newest first.
	sortKeysDesc(keys)

	rows := make([]map[string]any, 0, limit)
	for _, key := range keys {
		if len(rows) >= limit {
			break
		}
		entry, ok := decodeNodeLogKey(key, wantUUID)
		if !ok {
			continue
		}
		if !since.IsZero() && !entry.CreatedAt.After(since) {
			continue
		}
		body, err := r.getObject(key)
		if err != nil {
			log.Debug().Err(err).Str("key", key).Msg("s3 reader: skipping unreadable object")
			continue
		}
		decoded, err := decodeNodeLogBody(body, logType, env, wantUUID, entry.CreatedAt)
		if err != nil {
			continue
		}
		if search != "" && !nodeLogMatchesSearch(decoded, logType, search) {
			continue
		}
		rows = append(rows, decoded)
	}
	return rows, nil
}

// QueryResults implements LogReader. It lists the {env}/query/{name}/
// prefix (already name-scoped), applies the since filter, then pages.
// Because keys are chronologically ordered, page N is a contiguous slice
// of the sorted key list.
func (r *s3LogReader) QueryResults(env, name string, since time.Time, page, pageSize int) ([]map[string]any, int64, error) {
	if pageSize <= 0 {
		pageSize = 100
	}
	if pageSize > 1000 {
		pageSize = 1000
	}
	if page <= 0 {
		page = 1
	}
	prefix := env + "/query/" + name + "/"
	keys, err := r.listKeys(prefix)
	if err != nil {
		return nil, 0, err
	}
	// keys are oldest-first (lexical). Apply the since filter to narrow
	// the total before paging.
	if !since.IsZero() {
		filtered := keys[:0]
		for _, k := range keys {
			if ts, ok := tsFromKey(k); ok && ts.After(since) {
				filtered = append(filtered, k)
			}
		}
		keys = filtered
	}
	total := int64(len(keys))
	offset := (page - 1) * pageSize
	if offset >= len(keys) {
		return []map[string]any{}, total, nil
	}
	end := offset + pageSize
	if end > len(keys) {
		end = len(keys)
	}
	pageKeys := keys[offset:end]
	items := make([]map[string]any, 0, len(pageKeys))
	for _, key := range pageKeys {
		body, err := r.getObject(key)
		if err != nil {
			log.Debug().Err(err).Str("key", key).Msg("s3 reader: skipping unreadable query object")
			continue
		}
		item, err := decodeQueryLogBody(body, key)
		if err != nil {
			continue
		}
		items = append(items, item)
	}
	return items, total, nil
}

// StreamQueryResults implements LogReader. It lists every object under
// {env}/query/{name}/ (oldest-first) and invokes fn for each decoded
// OsqueryQueryData row. Memory is bounded by a single object body at a
// time; the key list itself can be large but is just strings.
func (r *s3LogReader) StreamQueryResults(env, name string, fn func(OsqueryQueryData) error) error {
	prefix := env + "/query/" + name + "/"
	keys, err := r.listKeys(prefix)
	if err != nil {
		return err
	}
	for _, key := range keys {
		body, err := r.getObject(key)
		if err != nil {
			return err
		}
		row, err := decodeQueryLogRow(body, key)
		if err != nil {
			return err
		}
		if err := fn(row); err != nil {
			return err
		}
	}
	return nil
}

// listKeys paginates ListObjectsV2 for a prefix and returns the keys in
// lexical (oldest-first) order.
func (r *s3LogReader) listKeys(prefix string) ([]string, error) {
	ctx := context.Background()
	var keys []string
	paginator := s3.NewListObjectsV2Paginator(r.client, &s3.ListObjectsV2Input{
		Bucket: aws.String(r.bucket),
		Prefix: aws.String(prefix),
	})
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("s3 list prefix %q: %w", prefix, err)
		}
		for _, obj := range page.Contents {
			if obj.Key == nil {
				continue
			}
			keys = append(keys, *obj.Key)
		}
	}
	// ListObjectsV2 returns keys in lexical order already; this sort is
	// a defensive no-op for well-behaved buckets.
	sort.Strings(keys)
	return keys, nil
}

// getObject downloads and returns the full body of an object.
func (r *s3LogReader) getObject(key string) ([]byte, error) {
	ctx := context.Background()
	out, err := r.client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(r.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, err
	}
	defer out.Body.Close()
	return io.ReadAll(out.Body)
}

// nodeLogEntry holds the parsed UUID + timestamp from a status/result key.
type nodeLogEntry struct {
	UUID      string
	CreatedAt time.Time
}

// decodeNodeLogKey parses {env}/{logType}/{uuid}:{ts}.json and reports
// whether the key belongs to wantUUID.
func decodeNodeLogKey(key, wantUUID string) (nodeLogEntry, bool) {
	base := key
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	// base is "{uuid}:{ts}.json"
	colon := strings.LastIndex(base, ":")
	if colon < 0 {
		return nodeLogEntry{}, false
	}
	uuidPart := base[:colon]
	if !strings.EqualFold(uuidPart, wantUUID) {
		return nodeLogEntry{}, false
	}
	tsStr := strings.TrimSuffix(base[colon+1:], ".json")
	tsMs, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return nodeLogEntry{}, false
	}
	return nodeLogEntry{UUID: wantUUID, CreatedAt: time.UnixMilli(tsMs)}, true
}

// decodeNodeLogBody decodes a status or result log object body into the
// same map[string]any shape the DB reader returns, so the API handler
// and frontend need no changes.
func decodeNodeLogBody(body []byte, logType, env, uuid string, createdAt time.Time) (map[string]any, error) {
	switch logType {
	case types.StatusLog:
		var logs []types.LogStatusData
		if err := json.Unmarshal(body, &logs); err != nil {
			return nil, err
		}
		// The DB reader produces one row per status line; mirror that.
		// We only return the first entry's map because the S3 write path
		// stores one batch per object — but the historical DB row shape
		// is per-line, so we emit the first line here. Callers that need
		// every line get them across multiple objects.
		if len(logs) == 0 {
			return nil, fmt.Errorf("empty status log")
		}
		l := logs[0]
		return map[string]any{
			"created_at":  createdAt,
			"uuid":        uuid,
			"environment": env,
			"line":        strconv.Itoa(int(l.Line)),
			"message":     l.Message,
			"version":     l.Version,
			"filename":    l.Filename,
			"severity":    strconv.Itoa(int(l.Severity)),
		}, nil
	case types.ResultLog:
		var logs []types.LogResultData
		if err := json.Unmarshal(body, &logs); err != nil {
			return nil, err
		}
		if len(logs) == 0 {
			return nil, fmt.Errorf("empty result log")
		}
		l := logs[0]
		return map[string]any{
			"created_at":  createdAt,
			"uuid":        uuid,
			"environment": env,
			"name":        l.Name,
			"action":      l.Action,
			"epoch":       l.Epoch,
			"columns":     string(l.Columns),
			"counter":     l.Counter,
		}, nil
	default:
		return nil, fmt.Errorf("invalid log type: %s", logType)
	}
}

// nodeLogMatchesSearch applies the same substring filter the DB reader
// applies via LOWER() LIKE. Best-effort, case-insensitive.
func nodeLogMatchesSearch(row map[string]any, logType, search string) bool {
	needle := strings.ToLower(search)
	fields := []string{"line", "message", "filename"}
	if logType == types.ResultLog {
		fields = []string{"name", "action", "columns"}
	}
	for _, f := range fields {
		if v, ok := row[f].(string); ok && strings.Contains(strings.ToLower(v), needle) {
			return true
		}
	}
	return false
}

// decodeQueryLogBody decodes a query result object into the map shape the
// DB reader's GetQueryResults returns.
func decodeQueryLogBody(body []byte, key string) (map[string]any, error) {
	row, err := decodeQueryLogRow(body, key)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"id":          int64(0),
		"created_at":  row.CreatedAt,
		"uuid":        row.UUID,
		"environment": row.Environment,
		"name":        row.Name,
		"data":        row.Data,
		"status":      row.Status,
	}, nil
}

// decodeQueryLogRow decodes a query result object into an OsqueryQueryData
// for the streaming path. The ID is synthetic (0) because S3 objects have
// no integer primary key; callers that need a unique identifier use the
// key itself.
func decodeQueryLogRow(body []byte, key string) (OsqueryQueryData, error) {
	var data types.QueryWriteData
	if err := json.Unmarshal(body, &data); err != nil {
		return OsqueryQueryData{}, err
	}
	env, uuid, _, ok := splitQueryKey(key)
	if !ok {
		return OsqueryQueryData{}, fmt.Errorf("could not parse query key %q", key)
	}
	return OsqueryQueryData{
		UUID:        upperUUID(uuid),
		Environment: env,
		Name:        data.Name,
		Data:        string(body),
		Status:      data.Status,
	}, nil
}

// splitQueryKey parses {env}/query/{name}/{uuid}:{ts}.json and returns
// env, uuid, name, ok.
func splitQueryKey(key string) (env, uuid, name string, ok bool) {
	parts := strings.SplitN(key, "/", 4)
	if len(parts) != 4 {
		return "", "", "", false
	}
	env = parts[0]
	// parts[1] == "query"
	name = parts[2]
	last := parts[3]
	colon := strings.LastIndex(last, ":")
	if colon < 0 {
		return "", "", "", false
	}
	uuid = last[:colon]
	return env, uuid, name, true
}

// tsFromKey extracts the millisecond timestamp from the trailing
// "{ts}.json" segment of any S3 log key.
func tsFromKey(key string) (time.Time, bool) {
	base := key
	if i := strings.LastIndex(base, "/"); i >= 0 {
		base = base[i+1:]
	}
	colon := strings.LastIndex(base, ":")
	if colon < 0 {
		return time.Time{}, false
	}
	tsStr := strings.TrimSuffix(base[colon+1:], ".json")
	tsMs, err := strconv.ParseInt(tsStr, 10, 64)
	if err != nil {
		return time.Time{}, false
	}
	return time.UnixMilli(tsMs), true
}

// sortKeysDesc sorts keys newest-first (descending lexical == descending
// chronological, because the timestamp is the last path segment).
func sortKeysDesc(keys []string) {
	sort.Sort(sort.Reverse(sort.StringSlice(keys)))
}
