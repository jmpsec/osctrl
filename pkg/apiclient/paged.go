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
// failed page returns an error together with the items fetched so far, which
// callers must not use.
func getAllPages[T any](api *OsctrlAPI, reqURL string) ([]T, error) {
	var all []T
	for page := 1; ; page++ {
		raw, err := api.GetGeneric(fmt.Sprintf("%s?page=%d&page_size=%d", reqURL, page, pagedPageSize), nil)
		if err != nil {
			return all, fmt.Errorf("error api request - %w - %s", err, string(raw))
		}
		var resp struct {
			Items      []T `json:"items"`
			TotalPages int `json:"total_pages"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return all, fmt.Errorf("can not parse body - %w", err)
		}
		all = append(all, resp.Items...)
		if page >= resp.TotalPages {
			return all, nil
		}
	}
}
