package apiclient

import (
	"encoding/json"
	"fmt"
)

// pagedPageSize is the largest page size the API honors.
const pagedPageSize = 500

// getAllPages follows the API's paged envelope ({items, total_pages}) and
// returns the items of every page. There is no page cap: this is meant for CLI
// use, and the server clamps page_size to 500 and reports total_pages. Any
// failed page returns nil and the error, never partial items.
func getAllPages[T any](api *OsctrlAPI, reqURL string) ([]T, error) {
	all, _, err := getPages[T](api, reqURL, 0)
	return all, err
}

// getPages is getAllPages with a cap: maxItems > 0 stops fetching once more
// than maxItems items exist, returns the first maxItems and truncated=true.
func getPages[T any](api *OsctrlAPI, reqURL string, maxItems int) (all []T, truncated bool, err error) {
	pageSize := pagedPageSize
	if maxItems > 0 && maxItems+1 < pageSize {
		pageSize = maxItems + 1 // one extra item tells whether there is more
	}
	for page := 1; ; page++ {
		raw, err := api.GetGeneric(fmt.Sprintf("%s?page=%d&page_size=%d", reqURL, page, pageSize), nil)
		if err != nil {
			return nil, false, fmt.Errorf("error api request - %w - %s", err, string(raw))
		}
		var resp struct {
			Items      []T `json:"items"`
			TotalPages int `json:"total_pages"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, false, fmt.Errorf("can not parse body - %w", err)
		}
		all = append(all, resp.Items...)
		if maxItems > 0 && len(all) > maxItems {
			return all[:maxItems], true, nil
		}
		if page >= resp.TotalPages {
			return all, false, nil
		}
	}
}
