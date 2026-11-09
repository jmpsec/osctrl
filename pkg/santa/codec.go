package santa

import (
	"compress/gzip"
	"compress/zlib"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	// MaxRawBody is the cap callers apply to the wire body with http.MaxBytesReader.
	MaxRawBody = 10 << 20
	// MaxDecodedBody caps the body after decompression (zip-bomb guard).
	MaxDecodedBody = 20 << 20
)

// ErrTooLarge is returned only when a size limit is exceeded.
var ErrTooLarge = errors.New("santa: body too large")

// Encoding records how the request was encoded so the response can match.
type Encoding struct{ Proto bool }

// Decode reads r.Body into msg, honoring Content-Type and Content-Encoding.
func Decode(r *http.Request, msg proto.Message) (Encoding, error) {
	var enc Encoding
	mt, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return enc, fmt.Errorf("santa: invalid content type: %w", err)
	}
	switch mt {
	case "application/x-protobuf", "application/protobuf", "application/octet-stream":
		enc.Proto = true
	case "application/json":
	default:
		return enc, fmt.Errorf("santa: unsupported content type %q", mt)
	}

	var body io.Reader = r.Body
	switch ce := strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))); ce {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(body)
		if err != nil {
			return enc, fmt.Errorf("santa: bad gzip body: %w", err)
		}
		defer zr.Close()
		body = zr
	case "deflate":
		zr, err := zlib.NewReader(body)
		if err != nil {
			return enc, fmt.Errorf("santa: bad deflate body: %w", err)
		}
		defer zr.Close()
		body = zr
	default:
		return enc, fmt.Errorf("santa: unsupported content encoding %q", ce)
	}

	data, err := io.ReadAll(io.LimitReader(body, MaxDecodedBody+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return enc, ErrTooLarge
		}
		return enc, fmt.Errorf("santa: reading body: %w", err)
	}
	if len(data) > MaxDecodedBody {
		return enc, ErrTooLarge
	}

	if enc.Proto {
		err = proto.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, msg)
	} else {
		err = protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(data, msg)
	}
	if err != nil {
		return enc, fmt.Errorf("santa: malformed body: %w", err)
	}
	return enc, nil
}

// Encode writes msg to w in the given encoding.
func Encode(w http.ResponseWriter, enc Encoding, msg proto.Message) error {
	var (
		out []byte
		err error
		ct  = "application/json"
	)
	if enc.Proto {
		ct = "application/x-protobuf"
		out, err = proto.Marshal(msg)
	} else {
		out, err = protojson.MarshalOptions{UseProtoNames: true}.Marshal(msg)
	}
	if err != nil {
		return err
	}
	w.Header().Set("Content-Type", ct)
	_, err = w.Write(out)
	return err
}
