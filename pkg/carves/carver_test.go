package carves

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// fakeS3 is a minimal path-style S3 endpoint covering the calls the carver
// makes: PutObject, CreateMultipartUpload, UploadPartCopy,
// CompleteMultipartUpload and GetObject.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte         // "bucket/key" -> body
	parts   map[string]map[int][]byte // uploadID -> part number -> body
}

func newFakeS3(t *testing.T) (*fakeS3, *s3.Client) {
	t.Helper()
	f := &fakeS3{objects: map[string][]byte{}, parts: map[string]map[int][]byte{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	client := s3.NewFromConfig(aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
	}, func(o *s3.Options) {
		o.BaseEndpoint = aws.String(srv.URL)
		o.UsePathStyle = true
	})
	return f, client
}

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	obj := strings.TrimPrefix(r.URL.Path, "/")
	q := r.URL.Query()
	switch {
	case r.Method == http.MethodPut && r.Header.Get("x-amz-copy-source") != "":
		src, err := url.QueryUnescape(r.Header.Get("x-amz-copy-source"))
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		data, ok := f.objects[strings.TrimPrefix(src, "/")]
		if !ok {
			http.Error(w, "no such copy source "+src, http.StatusNotFound)
			return
		}
		var part int
		if _, err := fmt.Sscanf(q.Get("partNumber"), "%d", &part); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		f.parts[q.Get("uploadId")][part] = data
		fmt.Fprintf(w, `<CopyPartResult><ETag>"etag-%d"</ETag></CopyPartResult>`, part)
	case r.Method == http.MethodPut:
		body, _ := io.ReadAll(r.Body)
		f.objects[obj] = body
		w.Header().Set("ETag", `"etag"`)
	case r.Method == http.MethodPost && q.Has("uploads"):
		id := fmt.Sprintf("upload-%d", len(f.parts)+1)
		f.parts[id] = map[int][]byte{}
		fmt.Fprintf(w, `<InitiateMultipartUploadResult><UploadId>%s</UploadId></InitiateMultipartUploadResult>`, id)
	case r.Method == http.MethodPost && q.Has("uploadId"):
		parts := f.parts[q.Get("uploadId")]
		var buf bytes.Buffer
		for i := 1; i <= len(parts); i++ {
			buf.Write(parts[i])
		}
		f.objects[obj] = buf.Bytes()
		fmt.Fprintf(w, `<CompleteMultipartUploadResult><Key>%s</Key></CompleteMultipartUploadResult>`, obj)
	case r.Method == http.MethodGet:
		data, ok := f.objects[obj]
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write(data)
	default:
		http.Error(w, "unsupported "+r.Method+" "+r.URL.String(), http.StatusNotImplemented)
	}
}

func testCarvesDB(t *testing.T) *gorm.DB {
	t.Helper()
	db, err := gorm.Open(sqlite.Open("file:"+t.Name()+"?mode=memory&cache=shared"), &gorm.Config{})
	require.NoError(t, err)
	return db
}

// carveBlocks creates a carve plus its blocks through the same calls the TLS
// carve handlers make, and returns the original file contents.
func carveBlocks(t *testing.T, c *Carves, chunks ...string) []byte {
	t.Helper()
	require.NoError(t, c.CreateCarve(CarvedFile{
		CarveID: "carve-1", RequestID: "req-1", SessionID: "sess-1", UUID: "NODE-1",
		Environment: "dev", Path: "/etc/hosts", TotalBlocks: len(chunks), EnvironmentID: 1,
	}))
	var all []byte
	for i, chunk := range chunks {
		data := base64.StdEncoding.EncodeToString([]byte(chunk))
		block := c.InitateBlock("dev", "NODE-1", "req-1", "sess-1", data, i, 1)
		require.NoError(t, c.CreateBlock(block, "NODE-1", data))
		all = append(all, chunk...)
	}
	return all
}

func TestCarverDBStoresBlocksAndArchivesLocally(t *testing.T) {
	c := CreateFileCarves(testCarvesDB(t), config.CarverDB, nil)
	want := carveBlocks(t, c, "hello ", "world")

	blocks, err := c.GetBlocks("sess-1")
	require.NoError(t, err)
	require.Len(t, blocks, 2)
	assert.Equal(t, base64.StdEncoding.EncodeToString([]byte("hello ")), blocks[0].Data)

	dir := t.TempDir()
	res, err := c.Archive("sess-1", dir)
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(dir, GenerateArchiveName(CarvedFile{UUID: "NODE-1", SessionID: "sess-1", Path: "/etc/hosts"})), res.File)
	got, err := os.ReadFile(res.File)
	require.NoError(t, err)
	assert.Equal(t, want, got)
}

func TestCarverS3UploadsBlocksAndArchivesToBucket(t *testing.T) {
	fake, client := newFakeS3(t)
	s3c := &CarverS3{S3Config: config.S3Carver{Bucket: "carves"}, Client: client}
	c := CreateFileCarves(testCarvesDB(t), config.CarverS3, s3c)
	want := carveBlocks(t, c, "hello ", "world")

	// The DB keeps only a pointer; the decoded bytes live in the bucket.
	blocks, err := c.GetBlocks("sess-1")
	require.NoError(t, err)
	require.Len(t, blocks, 2)
	assert.Equal(t, "s3://carves/dev:NODE-1:sess-1:0", blocks[0].Data)
	assert.Equal(t, []byte("hello "), fake.objects["carves/dev:NODE-1:sess-1:0"])

	res, err := c.Archive("sess-1", "")
	require.NoError(t, err)
	assert.Equal(t, "s3://carves/dev:NODE-1:sess-1:/etc/hosts.tar", res.File)
	assert.Equal(t, want, fake.objects["carves/dev:NODE-1:sess-1:/etc/hosts.tar"])

	// The API serves the archive from the same bucket.
	_, err = s3c.Download(CarvedFile{ArchivePath: res.File})
	require.NoError(t, err)
}

func TestCarverS3WithoutClientErrorsInsteadOfPanicking(t *testing.T) {
	c := CreateFileCarves(testCarvesDB(t), config.CarverS3, nil)
	require.NoError(t, c.CreateCarve(CarvedFile{CarveID: "c", SessionID: "sess-1", Environment: "dev"}))

	block := c.InitateBlock("dev", "NODE-1", "req-1", "sess-1", "aGk=", 0, 1)
	assert.ErrorContains(t, c.CreateBlock(block, "NODE-1", "aGk="), "s3 carver not initialized")
	_, err := c.Archive("sess-1", "")
	assert.ErrorContains(t, err, "s3 carver not initialized")
}

func TestCreateFileCarvesFromConfig(t *testing.T) {
	// Keep the AWS SDK from reading the developer's ~/.aws files.
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	s3ok := config.S3Carver{Bucket: "carves", Region: "us-east-1"}
	tests := []struct {
		name    string
		cfg     *config.YAMLConfigurationCarver
		want    string
		wantS3  bool
		wantErr string
	}{
		{name: "nil section defaults to db", cfg: nil, want: config.CarverDB},
		{name: "db", cfg: &config.YAMLConfigurationCarver{Type: config.CarverDB}, want: config.CarverDB},
		{name: "s3 with role credentials", cfg: &config.YAMLConfigurationCarver{Type: config.CarverS3, S3: &s3ok}, want: config.CarverS3, wantS3: true},
		{name: "s3 with static keys", cfg: &config.YAMLConfigurationCarver{Type: config.CarverS3, S3: &config.S3Carver{Bucket: "b", Region: "r", AccessKey: "k", SecretAccessKey: "s"}}, want: config.CarverS3, wantS3: true},
		{name: "s3 without section", cfg: &config.YAMLConfigurationCarver{Type: config.CarverS3}, wantErr: "carver.s3.bucket"},
		{name: "s3 without bucket", cfg: &config.YAMLConfigurationCarver{Type: config.CarverS3, S3: &config.S3Carver{Region: "r"}}, wantErr: "carver.s3.bucket"},
		{name: "s3 without region", cfg: &config.YAMLConfigurationCarver{Type: config.CarverS3, S3: &config.S3Carver{Bucket: "b"}}, wantErr: "carver.s3.region"},
		{name: "s3 key without secret", cfg: &config.YAMLConfigurationCarver{Type: config.CarverS3, S3: &config.S3Carver{Bucket: "b", Region: "r", AccessKey: "k"}}, wantErr: "accessKey and secretAccessKey"},
		{name: "local is rejected", cfg: &config.YAMLConfigurationCarver{Type: config.CarverLocal, Local: &config.LocalCarver{CarvesDir: "/tmp"}}, wantErr: `carver type "local" is not supported`},
		{name: "unknown is rejected", cfg: &config.YAMLConfigurationCarver{Type: "ftp"}, wantErr: "invalid carver method: ftp"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := CreateFileCarvesFromConfig(testCarvesDB(t), tt.cfg)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, c.Carver)
			assert.Equal(t, tt.wantS3, c.S3 != nil)
			if tt.wantS3 {
				assert.Equal(t, tt.cfg.S3.Bucket, c.S3.S3Config.Bucket)
			}
		})
	}
}

func TestCreateCarverS3UsesStaticKeysOnlyWhenConfigured(t *testing.T) {
	t.Setenv("AWS_CONFIG_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", filepath.Join(t.TempDir(), "none"))
	t.Setenv("AWS_ACCESS_KEY_ID", "ENVKEY")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "ENVSECRET")

	static, err := CreateCarverS3(config.S3Carver{Bucket: "b", Region: "r", AccessKey: "YAMLKEY", SecretAccessKey: "YAMLSECRET"})
	require.NoError(t, err)
	creds, err := static.AWSConfig.Credentials.Retrieve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "YAMLKEY", creds.AccessKeyID)

	// Without static keys the default chain (env, shared files, instance or
	// task role) must be used rather than empty static credentials.
	chain, err := CreateCarverS3(config.S3Carver{Bucket: "b", Region: "r"})
	require.NoError(t, err)
	creds, err = chain.AWSConfig.Credentials.Retrieve(t.Context())
	require.NoError(t, err)
	assert.Equal(t, "ENVKEY", creds.AccessKeyID)
}
