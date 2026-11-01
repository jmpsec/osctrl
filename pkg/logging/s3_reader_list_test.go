package logging

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
)

// fakeS3Bucket serves ListObjectsV2 (prefix, delimiter, start-after) and
// GetObject for one path-style bucket, counting list calls.
type fakeS3Bucket struct {
	objects map[string][]byte
	lists   atomic.Int64
}

func (f *fakeS3Bucket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.URL.Path, "/bucket/")
	q := r.URL.Query()
	if q.Get("list-type") != "2" {
		body, ok := f.objects[key]
		if !ok {
			http.Error(w, "no such key", http.StatusNotFound)
			return
		}
		_, _ = w.Write(body)
		return
	}
	f.lists.Add(1)
	prefix, delim, after := q.Get("prefix"), q.Get("delimiter"), q.Get("start-after")
	type entry struct {
		Key string `xml:"Key"`
	}
	type cp struct {
		Prefix string `xml:"Prefix"`
	}
	out := struct {
		XMLName        xml.Name `xml:"ListBucketResult"`
		Contents       []entry  `xml:"Contents"`
		CommonPrefixes []cp     `xml:"CommonPrefixes"`
		IsTruncated    bool     `xml:"IsTruncated"`
	}{}
	keys := make([]string, 0, len(f.objects))
	for k := range f.objects {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	seen := map[string]bool{}
	for _, k := range keys {
		if !strings.HasPrefix(k, prefix) || k <= after {
			continue
		}
		rest := k[len(prefix):]
		if i := strings.Index(rest, delim); delim != "" && i >= 0 {
			p := prefix + rest[:i+1]
			if !seen[p] {
				seen[p] = true
				out.CommonPrefixes = append(out.CommonPrefixes, cp{p})
			}
			continue
		}
		out.Contents = append(out.Contents, entry{k})
	}
	w.Header().Set("Content-Type", "application/xml")
	_ = xml.NewEncoder(w).Encode(out)
}

func statusObject(t *testing.T, msg string) []byte {
	t.Helper()
	b, err := json.Marshal([]types.LogStatusData{{Message: msg}})
	require.NoError(t, err)
	return b
}

// A recent page reads only the newest day folders, not the whole history,
// and undated keys written before day folders are still returned.
func TestS3NodeLogsListsOnlyTheDaysItNeeds(t *testing.T) {
	f := &fakeS3Bucket{objects: map[string][]byte{}}
	day := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for i := range 30 {
		ts := day.AddDate(0, 0, i)
		f.objects[s3LogKey("env", "status", "NODE", ts, "a")] = statusObject(t, ts.Format(s3DayLayout))
	}
	legacyTS := day.AddDate(0, -1, 0)
	f.objects["env/status/NODE/"+s3KeyName(legacyTS, "old")] = statusObject(t, "legacy")
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	client := s3.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("a", "b", "")},
		func(o *s3.Options) { o.BaseEndpoint = aws.String(srv.URL); o.UsePathStyle = true })
	r := NewS3LogReader(client, "bucket")

	rows, err := r.NodeLogs(types.StatusLog, "env", "node", time.Time{}, 2, "", "")
	require.NoError(t, err)
	require.Len(t, rows, 2)
	require.Equal(t, "2026-10-30", rows[0]["message"])
	require.Equal(t, "2026-10-29", rows[1]["message"])
	require.LessOrEqual(t, f.lists.Load(), int64(3), "one day listing plus the two newest days")

	rows, err = r.NodeLogs(types.StatusLog, "env", "node", time.Time{}, 100, "", "")
	require.NoError(t, err)
	require.Len(t, rows, 31)
	require.Equal(t, "legacy", rows[30]["message"])
}
