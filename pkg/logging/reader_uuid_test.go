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
	name  string
	uuids []string
	want  int
}{
	{"nil is no filter", nil, 3},
	{"one uuid", []string{"a"}, 1},
	{"empty slice is no rows", []string{}, 0},
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
			items, total, err := r.QueryResults("env", "q", tc.uuids, time.Time{}, 1, 100)
			require.NoError(t, err)
			require.Len(t, items, tc.want)
			require.EqualValues(t, tc.want, total)
			n := 0
			require.NoError(t, r.StreamQueryResults("env", "q", tc.uuids, func(OsqueryQueryData) error { n++; return nil }))
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
			items, total, err := r.QueryResults("env", "q", tc.uuids, time.Time{}, 1, 100)
			require.NoError(t, err)
			require.Len(t, items, tc.want)
			require.EqualValues(t, tc.want, total)
			n := 0
			require.NoError(t, r.StreamQueryResults("env", "q", tc.uuids, func(OsqueryQueryData) error { n++; return nil }))
			require.Equal(t, tc.want, n)
		})
	}
}
