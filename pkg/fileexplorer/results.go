package fileexplorer

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/types"
)

func decodeEntries(data []byte) ([]Entry, error) {
	var wrapped types.QueryWriteData
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Result != nil {
		data = wrapped.Result
	}

	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(rows))
	for _, row := range rows {
		entries = append(entries, Entry{
			Path:      stringValue(row["path"]),
			Filename:  stringValue(row["filename"]),
			Directory: stringValue(row["directory"]),
			Type:      stringValue(row["type"]),
			Size:      int64Value(row["size"]),
			Mode:      stringValue(row["mode"]),
			UID:       stringValue(row["uid"]),
			GID:       stringValue(row["gid"]),
			MTime:     int64Value(row["mtime"]),
			ATime:     int64Value(row["atime"]),
			CTime:     int64Value(row["ctime"]),
		})
	}
	return entries, nil
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func int64Value(value any) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		i, _ := v.Int64()
		return i
	case string:
		i, _ := strconv.ParseInt(v, 10, 64)
		return i
	default:
		return 0
	}
}
