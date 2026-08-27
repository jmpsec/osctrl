package logsinks

// Data categories that can be routed to individual log sinks. Each
// category corresponds to a class of osquery data that osctrl-tls
// receives and dispatches through the exporter fan-out.
const (
	// CatStatus is osquery daemon status logs (INFO/WARN/ERROR),
	// received via POST /{env}/log with logType=status.
	CatStatus = "status"
	// CatResult is scheduled-query result logs, received via
	// POST /{env}/log with logType=result.
	CatResult = "result"
	// CatQuery is on-demand distributed-query results, received via
	// POST /{env}/write.
	CatQuery = "query"
	// CatCarveMeta is carve lifecycle metadata (scheduling, init,
	// completion). Emitted by the carve handlers as a small JSON
	// event so external sinks can track carve lifecycle without
	// reading the osctrl DB.
	CatCarveMeta = "carve.meta"
	// CatCarveData is carve block metadata (block ID, session ID,
	// size). Emitted per block so external sinks know a carve is
	// progressing. The raw block payload is NOT sent through the
	// fan-out — it is stored by pkg/carves in the DB or S3 directly.
	CatCarveData = "carve.data"
)

// AllCategories is the complete set of valid category strings, used for
// validation and UI defaults.
var AllCategories = []string{
	CatStatus,
	CatResult,
	CatQuery,
	CatCarveMeta,
	CatCarveData,
}

// allCategoriesSet is a set for O(1) validation lookups.
var allCategoriesSet = func() map[string]struct{} {
	m := make(map[string]struct{}, len(AllCategories))
	for _, c := range AllCategories {
		m[c] = struct{}{}
	}
	return m
}()

// IsValidCategory returns true if cat is a known category string.
func IsValidCategory(cat string) bool {
	_, ok := allCategoriesSet[cat]
	return ok
}

// ValidateCategories returns nil if every entry in cats is a known
// category string. Otherwise it returns the first unknown entry as an
// error.
func ValidateCategories(cats []string) error {
	for _, c := range cats {
		if !IsValidCategory(c) {
			return &invalidCategoryError{Category: c}
		}
	}
	return nil
}

// MatchesCategory returns true if the sink should receive the given
// category. An empty categories list means "all categories"
// (backwards-compatible default when a single sink is configured).
func MatchesCategory(categories []string, cat string) bool {
	if len(categories) == 0 {
		return true
	}
	for _, c := range categories {
		if c == cat {
			return true
		}
	}
	return false
}

// IsAllCategories returns true when categories is empty or nil, meaning
// the sink receives every category. Used by the API to normalize the
// stored value: an explicit list of all five categories is collapsed to
// empty so the stored value stays clean.
func IsAllCategories(categories []string) bool {
	return len(categories) == 0
}

// NormalizeCategories collapses an explicit "all" list (all five
// categories) to empty so the stored value stays clean. A subset is
// returned as-is. Unknown entries are rejected.
func NormalizeCategories(cats []string) ([]string, error) {
	if len(cats) == 0 {
		return nil, nil
	}
	if err := ValidateCategories(cats); err != nil {
		return nil, err
	}
	if len(cats) == len(AllCategories) {
		all := true
		for _, c := range cats {
			if !IsValidCategory(c) {
				all = false
				break
			}
		}
		if all {
			return nil, nil
		}
	}
	return cats, nil
}

type invalidCategoryError struct {
	Category string
}

func (e *invalidCategoryError) Error() string {
	return "invalid log sink category: " + e.Category
}
