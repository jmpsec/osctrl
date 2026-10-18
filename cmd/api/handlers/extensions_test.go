package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/extensions"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func setupExtensionsHandlers(t *testing.T) (*HandlersApi, *gorm.DB, environments.TLSEnvironment) {
	t.Helper()
	dsn := "file:" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name()) + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{TranslateError: true})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() { _ = sqlDB.Close() })
	envs := environments.CreateEnvironment(db)
	userManager := users.CreateUserManager(db)
	auditLog, err := auditlog.CreateAuditLogManager(db, "osctrl-api", true)
	require.NoError(t, err)
	mgr, err := extensions.NewManager(db)
	require.NoError(t, err)

	envA := environments.TLSEnvironment{UUID: "env-a", Name: "a", Configuration: "{}"}
	require.NoError(t, db.Create(&envA).Error)
	require.NoError(t, userManager.Create(users.AdminUser{Username: "alice"}))
	require.NoError(t, userManager.Create(users.AdminUser{Username: "bob"}))
	require.NoError(t, userManager.Create(users.AdminUser{Username: "root", Admin: true}))
	require.NoError(t, userManager.CreatePermission(users.UserPermission{
		Username: "alice", AccessType: int(users.AdminLevel), AccessValue: true, Environment: envA.UUID, EnvironmentID: envA.ID,
	}))

	h := CreateHandlersApi(
		WithDB(db), WithEnvs(envs), WithUsers(userManager), WithAuditLog(auditLog),
		WithExtensions(mgr), WithDebugHTTP(&config.YAMLConfigurationDebug{}),
	)
	return h, db, envA
}

type extCall struct {
	method, path string
	handler      func(*HandlersApi) http.HandlerFunc
	vals         map[string]string
}

func extReq(t *testing.T, h *HandlersApi, c extCall, user string, body io.Reader, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(c.method, c.path, body)
	req.RemoteAddr = "127.0.0.1:1234"
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range c.vals {
		req.SetPathValue(k, v)
	}
	req = req.WithContext(context.WithValue(req.Context(), ContextKey(contextAPI), ContextValue{ctxUser: user}))
	rr := httptest.NewRecorder()
	c.handler(h)(rr, req)
	return rr
}

func callList() extCall {
	return extCall{http.MethodGet, "/api/v1/extensions", func(h *HandlersApi) http.HandlerFunc { return h.ExtensionsListHandler }, nil}
}

func callCreate() extCall {
	return extCall{http.MethodPost, "/api/v1/extensions", func(h *HandlersApi) http.HandlerFunc { return h.ExtensionsCreateHandler }, nil}
}

func callUpdate(id uint) extCall {
	return extCall{http.MethodPatch, fmt.Sprintf("/api/v1/extensions/%d", id),
		func(h *HandlersApi) http.HandlerFunc { return h.ExtensionsUpdateHandler }, map[string]string{"id": fmt.Sprint(id)}}
}

func callDelete(id uint) extCall {
	return extCall{http.MethodDelete, fmt.Sprintf("/api/v1/extensions/%d", id),
		func(h *HandlersApi) http.HandlerFunc { return h.ExtensionsDeleteHandler }, map[string]string{"id": fmt.Sprint(id)}}
}

func callFile(method string, id uint, platform, arch string) extCall {
	hf := func(h *HandlersApi) http.HandlerFunc { return h.ExtensionFilePutHandler }
	if method == http.MethodDelete {
		hf = func(h *HandlersApi) http.HandlerFunc { return h.ExtensionFileDeleteHandler }
	}
	return extCall{method, fmt.Sprintf("/api/v1/extensions/%d/files/%s/%s", id, platform, arch), hf,
		map[string]string{"id": fmt.Sprint(id), "platform": platform, "arch": arch}}
}

func createExt(t *testing.T, h *HandlersApi, name string, cmdExec bool) types.ExtensionView {
	t.Helper()
	body := fmt.Sprintf(`{"name":%q,"description":"d","version":"1.0","command_execution":%v}`, name, cmdExec)
	rr := extReq(t, h, callCreate(), "root", strings.NewReader(body), "application/json")
	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	var v types.ExtensionView
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &v))
	return v
}

// content returns n deterministic bytes for seed.
func content(n, seed int64) io.Reader {
	return io.LimitReader(rand.New(rand.NewSource(seed)), n)
}

func contentSHA(t *testing.T, n, seed int64) string {
	t.Helper()
	hs := sha256.New()
	_, err := io.Copy(hs, content(n, seed))
	require.NoError(t, err)
	return hex.EncodeToString(hs.Sum(nil))
}

// multipartBody streams a multipart body with field holding data, so the
// test never holds the whole upload in memory either.
func multipartBody(t *testing.T, field, filename string, data io.Reader) (io.Reader, string) {
	t.Helper()
	pr, pw := io.Pipe()
	mw := multipart.NewWriter(pw)
	go func() {
		part, err := mw.CreateFormFile(field, filename)
		if err == nil {
			_, err = io.Copy(part, data)
		}
		if err == nil {
			err = mw.Close()
		}
		pw.CloseWithError(err)
	}()
	t.Cleanup(func() { _ = pr.Close() })
	return pr, mw.FormDataContentType()
}

func upload(t *testing.T, h *HandlersApi, id uint, platform, arch string, n, seed int64) *httptest.ResponseRecorder {
	t.Helper()
	body, ct := multipartBody(t, "file", "ext.ext", content(n, seed))
	return extReq(t, h, callFile(http.MethodPut, id, platform, arch), "root", body, ct)
}

func listExts(t *testing.T, h *HandlersApi) []types.ExtensionView {
	t.Helper()
	rr := extReq(t, h, callList(), "root", nil, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var out []types.ExtensionView
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &out))
	return out
}

func settingLines(t *testing.T, db *gorm.DB) []string {
	t.Helper()
	return auditLines(t, db, auditlog.LogTypeSetting, auditlog.NoEnvironment)
}

func TestExtensionsPermissions(t *testing.T) {
	h, db, _ := setupExtensionsHandlers(t)
	ext := createExt(t, h, "ext1", false)

	calls := []struct {
		c    extCall
		body string
	}{
		{callList(), ""},
		{callCreate(), `{"name":"ext2"}`},
		{callUpdate(ext.ID), `{"description":"x"}`},
		{callDelete(ext.ID), ""},
		{callFile(http.MethodPut, ext.ID, "linux", "amd64"), ""},
		{callFile(http.MethodDelete, ext.ID, "linux", "amd64"), ""},
	}
	for _, user := range []string{"alice", "bob"} {
		for _, c := range calls {
			before := len(settingLines(t, db))
			rr := extReq(t, h, c.c, user, strings.NewReader(c.body), "application/json")
			require.Equal(t, http.StatusForbidden, rr.Code, "%s %s %s", user, c.c.method, c.c.path)
			lines := settingLines(t, db)
			require.Len(t, lines, before+1, "%s %s %s", user, c.c.method, c.c.path)
			require.Contains(t, lines[len(lines)-1], "denied access for user "+user)
		}
	}
	got := listExts(t, h)
	require.Len(t, got, 1, "denied requests must not change the library")
	require.Equal(t, "d", got[0].Description)
}

func TestExtensionsCRUD(t *testing.T) {
	h, db, envA := setupExtensionsHandlers(t)
	ext := createExt(t, h, "ext1", false)
	require.Equal(t, "ext1", ext.Name)
	require.Equal(t, "root", ext.CreatedBy)
	require.NotNil(t, ext.Files)

	// Invalid name, duplicate, oversize description.
	for body, code := range map[string]int{
		`{"name":"bad name"}`: http.StatusBadRequest,
		`{"name":"ext1"}`:     http.StatusConflict,
		`{"name":"EXT1"}`:     http.StatusConflict,
		`not json`:            http.StatusBadRequest,
		`{"name":"ext3","description":"` + strings.Repeat("x", 1025) + `"}`: http.StatusBadRequest,
	} {
		rr := extReq(t, h, callCreate(), "root", strings.NewReader(body), "application/json")
		require.Equal(t, code, rr.Code, "%.40s: %s", body, rr.Body.String())
	}

	// PATCH only changes the fields that are set.
	rr := extReq(t, h, callUpdate(ext.ID), "root", strings.NewReader(`{"version":"2.0"}`), "application/json")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var v types.ExtensionView
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &v))
	require.Equal(t, "2.0", v.Version)
	require.Equal(t, "d", v.Description)
	require.False(t, v.CommandExecution)

	rr = extReq(t, h, callUpdate(999), "root", strings.NewReader(`{"version":"2.0"}`), "application/json")
	require.Equal(t, http.StatusNotFound, rr.Code)

	// Assigned: flipping command execution and deleting are refused.
	require.NoError(t, h.Extensions.AssignEnv(envA.ID, ext.ID, "root"))
	got := listExts(t, h)
	require.Len(t, got, 1)
	require.Equal(t, 1, got[0].Environments)
	require.Equal(t, 0, got[0].Nodes)
	rr = extReq(t, h, callUpdate(ext.ID), "root", strings.NewReader(`{"command_execution":true}`), "application/json")
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())
	rr = extReq(t, h, callDelete(ext.ID), "root", nil, "")
	require.Equal(t, http.StatusConflict, rr.Code, rr.Body.String())

	require.NoError(t, h.Extensions.UnassignEnv(envA.ID, ext.ID))
	rr = extReq(t, h, callUpdate(ext.ID), "root", strings.NewReader(`{"command_execution":true,"description":"new"}`), "application/json")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	rr = extReq(t, h, callDelete(ext.ID), "root", nil, "")
	require.Equal(t, http.StatusNoContent, rr.Code, rr.Body.String())
	require.Empty(t, listExts(t, h))
	rr = extReq(t, h, callDelete(ext.ID), "root", nil, "")
	require.Equal(t, http.StatusNotFound, rr.Code)

	lines := strings.Join(settingLines(t, db), "\n")
	require.Contains(t, lines, "created extension ext1 (command execution false)")
	require.Contains(t, lines, "updated extension ext1: version")
	require.Contains(t, lines, "updated extension ext1: description, command_execution")
	require.Contains(t, lines, "deleted extension ext1")
}

func TestExtensionsUpload(t *testing.T) {
	h, db, _ := setupExtensionsHandlers(t)
	ext := createExt(t, h, "ext1", false)

	rr := upload(t, h, ext.ID, "linux", "amd64", 1<<20, 1)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	var f types.ExtensionFileView
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &f))
	sha1MiB := contentSHA(t, 1<<20, 1)
	require.Equal(t, sha1MiB, f.SHA256)
	require.Equal(t, int64(1<<20), f.Size)
	require.Equal(t, "ext.ext", f.Filename)
	require.Equal(t, "root", f.UpdatedBy)

	// Replace changes the SHA-256.
	rr = upload(t, h, ext.ID, "linux", "amd64", 1<<20, 2)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	got := listExts(t, h)
	require.Len(t, got[0].Files, 1)
	require.Equal(t, contentSHA(t, 1<<20, 2), got[0].Files[0].SHA256)

	// Exactly 64 MiB is accepted.
	rr = upload(t, h, ext.ID, "linux", "arm64", extensions.MaxFileSize, 3)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &f))
	require.Equal(t, int64(extensions.MaxFileSize), f.Size)
	require.Equal(t, contentSHA(t, extensions.MaxFileSize, 3), f.SHA256)

	var chunksBefore int64
	require.NoError(t, db.Model(&extensions.ExtensionChunk{}).Count(&chunksBefore).Error)

	// 64 MiB + 1 is refused and stores nothing.
	rr = upload(t, h, ext.ID, "darwin", "universal", extensions.MaxFileSize+1, 4)
	require.Equal(t, http.StatusRequestEntityTooLarge, rr.Code, rr.Body.String())
	// A body over the cap before the file part is stopped by the body limit.
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	mw := multipart.NewWriter(pw)
	go func() {
		pad, _ := mw.CreateFormField("pad")
		_, err := io.Copy(pad, content(extensions.MaxFileSize+2<<20, 4))
		pw.CloseWithError(err)
	}()
	rr = extReq(t, h, callFile(http.MethodPut, ext.ID, "darwin", "universal"), "root", pr, mw.FormDataContentType())
	require.Equal(t, http.StatusRequestEntityTooLarge, rr.Code, rr.Body.String())
	var chunksAfter int64
	require.NoError(t, db.Model(&extensions.ExtensionChunk{}).Count(&chunksAfter).Error)
	require.Equal(t, chunksBefore, chunksAfter)
	require.Len(t, listExts(t, h)[0].Files, 2)

	// Empty file, bad platform or arch, missing file part, unknown extension.
	rr = upload(t, h, ext.ID, "windows", "amd64", 0, 5)
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	rr = upload(t, h, ext.ID, "freebsd", "amd64", 10, 5)
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	rr = upload(t, h, ext.ID, "windows", "arm64", 10, 5)
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	body, ct := multipartBody(t, "other", "x", content(10, 5))
	rr = extReq(t, h, callFile(http.MethodPut, ext.ID, "windows", "amd64"), "root", body, ct)
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	rr = extReq(t, h, callFile(http.MethodPut, ext.ID, "windows", "amd64"), "root", strings.NewReader("{}"), "application/json")
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	rr = upload(t, h, 999, "windows", "amd64", 10, 5)
	require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())

	// A truncated body (client gone) stores nothing.
	pr, pw = io.Pipe()
	mw = multipart.NewWriter(pw)
	go func() {
		part, _ := mw.CreateFormFile("file", "x")
		_, _ = io.Copy(part, content(10, 6))
		_ = pw.Close() // no closing boundary
	}()
	rr = extReq(t, h, callFile(http.MethodPut, ext.ID, "windows", "amd64"), "root", pr, mw.FormDataContentType())
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), "cut short")
	require.Len(t, listExts(t, h)[0].Files, 2)

	// Delete a file.
	rr = extReq(t, h, callFile(http.MethodDelete, ext.ID, "linux", "arm64"), "root", nil, "")
	require.Equal(t, http.StatusNoContent, rr.Code, rr.Body.String())
	rr = extReq(t, h, callFile(http.MethodDelete, ext.ID, "linux", "arm64"), "root", nil, "")
	require.Equal(t, http.StatusNotFound, rr.Code, rr.Body.String())
	require.Len(t, listExts(t, h)[0].Files, 1)

	lines := strings.Join(settingLines(t, db), "\n")
	require.Contains(t, lines, fmt.Sprintf("uploaded linux/amd64 file for extension ext1: sha256=%s size=%d", sha1MiB, 1<<20))
	require.Contains(t, lines, "deleted linux/arm64 file for extension ext1")
}

func TestSanitizeExtensionFilename(t *testing.T) {
	for in, want := range map[string]string{
		"ext.ext":                "ext.ext",
		`C:\Users\x\ext.exe`:     "ext.exe",
		"a/b/../c.ext":           "c.ext",
		"evil\r\nname\x00.ext":   "evilname.ext",
		strings.Repeat("é", 300): strings.Repeat("é", 127),
		"":                       "",
		"..":                     "",
	} {
		require.Equal(t, want, sanitizeFilename(in), "%q", in)
	}
}
