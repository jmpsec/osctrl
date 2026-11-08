package logging

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

var uuidFilterCases = []struct {
	name   string
	filter NodeFilter
	want   int
}{
	{"zero is no filter", NodeFilter{}, 3},
	{"one uuid", NodeFilter{Only: []string{"a"}}, 1},
	{"empty only is no rows", NodeFilter{Only: []string{}}, 0},
	{"except one", NodeFilter{Except: []string{"b"}}, 2},
	{"empty except drops nothing", NodeFilter{Except: []string{}}, 3},
	{"except wins over only", NodeFilter{Only: []string{"a", "b"}, Except: []string{"b"}}, 1},
}

func TestQueryResultsUUIDFilterDB(t *testing.T) {
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&OsqueryQueryData{}))
	for _, u := range []string{"A", "B", "C"} {
		require.NoError(t, db.Create(&OsqueryQueryData{UUID: u, Name: "q", Data: "[]"}).Error)
	}
	r := NewDBLogReader(db)
	for _, tc := range uuidFilterCases {
		t.Run(tc.name, func(t *testing.T) {
			items, total, err := r.QueryResults("env", "q", tc.filter, time.Time{}, 1, 100)
			require.NoError(t, err)
			require.Len(t, items, tc.want)
			require.EqualValues(t, tc.want, total)
			n := 0
			require.NoError(t, r.StreamQueryResults("env", "q", tc.filter, func(OsqueryQueryData) error { n++; return nil }))
			require.Equal(t, tc.want, n)
		})
	}
}

func TestQueryResultsUUIDFilterS3(t *testing.T) {
	f := &fakeS3Bucket{objects: map[string][]byte{}}
	body, err := json.Marshal(types.QueryWriteData{Name: "q"})
	require.NoError(t, err)
	ts := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	for _, u := range []string{"A", "B", "C"} {
		f.objects[s3QueryKey("env", "q", u, ts, "x")] = body
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	client := s3.NewFromConfig(aws.Config{Region: "us-east-1", Credentials: credentials.NewStaticCredentialsProvider("a", "b", "")},
		func(o *s3.Options) { o.BaseEndpoint = aws.String(srv.URL); o.UsePathStyle = true })
	r := NewS3LogReader(client, "bucket")
	for _, tc := range uuidFilterCases {
		t.Run(tc.name, func(t *testing.T) {
			items, total, err := r.QueryResults("env", "q", tc.filter, time.Time{}, 1, 100)
			require.NoError(t, err)
			require.Len(t, items, tc.want)
			require.EqualValues(t, tc.want, total)
			n := 0
			require.NoError(t, r.StreamQueryResults("env", "q", tc.filter, func(OsqueryQueryData) error { n++; return nil }))
			require.Equal(t, tc.want, n)
		})
	}
}
