package santa

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"buf.build/gen/go/northpolesec/protos/protocolbuffers/go/syncv2"
	"google.golang.org/protobuf/proto"
)

func newReq(t *testing.T, body []byte, ct, ce string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/preflight/X", bytes.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	if ce != "" {
		r.Header.Set("Content-Encoding", ce)
	}
	return r
}

func gz(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// The Santa descriptor pins json_name (e.g. serial_number -> "serial_num"), so protojson
// accepts the proto name and the pinned JSON name, not lowerCamelCase.
func TestDecodeJSONProtoAndJSONNames(t *testing.T) {
	for _, body := range []string{`{"serial_number":"X"}`, `{"serial_num":"X"}`} {
		var m syncv2.PreflightRequest
		enc, err := Decode(newReq(t, []byte(body), "application/json; charset=utf-8", ""), &m)
		if err != nil || enc.Proto || m.GetSerialNumber() != "X" {
			t.Fatalf("%s: enc=%+v err=%v sn=%q", body, enc, err, m.GetSerialNumber())
		}
	}
}

func TestDecodeProtoDeflate(t *testing.T) {
	raw, err := proto.Marshal(&syncv2.PreflightRequest{MachineId: "X"})
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	for _, ct := range []string{"application/x-protobuf", "application/protobuf", "application/octet-stream"} {
		var m syncv2.PreflightRequest
		enc, err := Decode(newReq(t, buf.Bytes(), ct, "deflate"), &m)
		if err != nil || !enc.Proto || m.GetMachineId() != "X" {
			t.Fatalf("%s: enc=%+v err=%v", ct, enc, err)
		}
	}
}

func TestDecodeGzipJSON(t *testing.T) {
	var m syncv2.PreflightRequest
	_, err := Decode(newReq(t, gz(t, []byte(`{"machine_id":"X"}`)), "application/json", "gzip"), &m)
	if err != nil || m.GetMachineId() != "X" {
		t.Fatalf("err=%v id=%q", err, m.GetMachineId())
	}
}

func TestDecodeRejectsOversizedDecompressed(t *testing.T) {
	var m syncv2.PreflightRequest
	_, err := Decode(newReq(t, gz(t, make([]byte, MaxDecodedBody+1)), "application/octet-stream", "gzip"), &m)
	if !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}

func TestDecodeRejectsOversizedPlain(t *testing.T) {
	var m syncv2.PreflightRequest
	body := []byte(`{"machine_id":"` + strings.Repeat("a", MaxDecodedBody) + `"}`)
	if _, err := Decode(newReq(t, body, "application/json", ""), &m); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
	// A caller-side MaxBytesReader overflow also maps to ErrTooLarge.
	r := newReq(t, []byte(`{"machine_id":"XXXXXXXX"}`), "application/json", "")
	r.Body = http.MaxBytesReader(httptest.NewRecorder(), r.Body, 5)
	if _, err := Decode(r, &m); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("want ErrTooLarge for MaxBytesReader, got %v", err)
	}
}

func TestDecodeErrorsAreNotTooLarge(t *testing.T) {
	cases := []struct{ name, body, ct, ce string }{
		{"bad json", `{`, "application/json", ""},
		{"bad proto", "\xff\xff\xff", "application/x-protobuf", ""},
		{"bad gzip", "nope", "application/json", "gzip"},
		{"unknown encoding", `{}`, "application/json", "br"},
		{"unknown type", `{}`, "text/plain", ""},
		{"missing type", `{}`, "", ""},
	}
	for _, c := range cases {
		var m syncv2.PreflightRequest
		_, err := Decode(newReq(t, []byte(c.body), c.ct, c.ce), &m)
		if err == nil || errors.Is(err, ErrTooLarge) {
			t.Errorf("%s: got %v", c.name, err)
		}
	}
}

func TestDecodeUnknownFieldsIgnored(t *testing.T) {
	var m syncv2.PreflightRequest
	if _, err := Decode(newReq(t, []byte(`{"machine_id":"X","bogus":1}`), "application/json", ""), &m); err != nil {
		t.Fatal(err)
	}
}

func TestEncodeUsesProtoNames(t *testing.T) {
	w := httptest.NewRecorder()
	resp := &syncv2.PreflightResponse{ClientMode: syncv2.ClientMode_LOCKDOWN}
	if err := Encode(w, Encoding{}, resp); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(w.Body.String(), `"client_mode"`) || w.Header().Get("Content-Type") != "application/json" {
		t.Fatalf("%s %v", w.Body.String(), w.Header())
	}
	w = httptest.NewRecorder()
	if err := Encode(w, Encoding{Proto: true}, resp); err != nil {
		t.Fatal(err)
	}
	var back syncv2.PreflightResponse
	if err := proto.Unmarshal(w.Body.Bytes(), &back); err != nil || back.GetClientMode() != syncv2.ClientMode_LOCKDOWN ||
		w.Header().Get("Content-Type") != "application/x-protobuf" {
		t.Fatalf("err=%v hdr=%v", err, w.Header())
	}
}
