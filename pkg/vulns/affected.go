package vulns

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/google/osv-scalibr/semantic"
)

// Range is one OSV range: events of a single type.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is one OSV range event; exactly one field is set.
type Event struct {
	Introduced   string `json:"introduced,omitempty"`
	Fixed        string `json:"fixed,omitempty"`
	LastAffected string `json:"last_affected,omitempty"`
	Limit        string `json:"limit,omitempty"`
}

// ErrUnassessable means a version could not be compared. The package is
// reported as "not assessed", never as "not affected".
var ErrUnassessable = errors.New("version cannot be assessed")

// assessableVersion is the guard the comparators lack: they parse any
// string, so a version without a digit would silently compare as something.
func assessableVersion(v string) bool {
	return strings.ContainsAny(v, "0123456789")
}

// isAffected reports whether version is affected by an advisory's ranges or
// explicit versions list, and the version that fixes it when one is known.
func isAffected(ecosystem, version string, ranges []Range, versions []string) (bool, string, error) {
	listed := slices.Contains(versions, version)
	v, err := semantic.Parse(version, ecosystem)
	if err != nil {
		if listed {
			return true, "", nil
		}
		return false, "", fmt.Errorf("%w: %w", ErrUnassessable, err)
	}
	for _, r := range ranges {
		if r.Type != "ECOSYSTEM" && r.Type != "SEMVER" {
			continue
		}
		hit, fixed, err := inRange(ecosystem, v, r.Events)
		if err != nil {
			return false, "", err
		}
		if hit {
			return true, fixed, nil
		}
	}
	return listed, "", nil
}

const (
	kindIntroduced   = "introduced"
	kindFixed        = "fixed"
	kindLastAffected = "last_affected"
)

type rangeEvent struct {
	kind string
	raw  string
	ver  semantic.Version // nil for introduced "0", which sorts first
}

// inRange walks a range's events in version order. Introduced opens an
// affected span, fixed closes it at that version, and last_affected closes it
// just after that version.
func inRange(ecosystem string, v semantic.Version, events []Event) (bool, string, error) {
	var evs []rangeEvent
	for _, e := range events {
		switch {
		case e.Introduced != "":
			evs = append(evs, rangeEvent{kind: kindIntroduced, raw: e.Introduced})
		case e.Fixed != "":
			evs = append(evs, rangeEvent{kind: kindFixed, raw: e.Fixed})
		case e.LastAffected != "":
			evs = append(evs, rangeEvent{kind: kindLastAffected, raw: e.LastAffected})
		}
	}
	for i := range evs {
		if evs[i].kind == kindIntroduced && evs[i].raw == "0" {
			continue
		}
		p, err := semantic.Parse(evs[i].raw, ecosystem)
		if err != nil {
			return false, "", fmt.Errorf("%w: event %q: %w", ErrUnassessable, evs[i].raw, err)
		}
		evs[i].ver = p
	}
	var sortErr error
	sort.SliceStable(evs, func(i, j int) bool {
		a, b := evs[i].ver, evs[j].ver
		if a == nil || b == nil {
			return a == nil && b != nil
		}
		c, err := a.Compare(b)
		if err != nil {
			sortErr = err
		}
		return c < 0
	})
	if sortErr != nil {
		return false, "", fmt.Errorf("%w: %w", ErrUnassessable, sortErr)
	}

	affected := false
	for _, e := range evs {
		c := 1 // introduced "0": every version is above it
		if e.ver != nil {
			var err error
			if c, err = v.Compare(e.ver); err != nil {
				return false, "", fmt.Errorf("%w: %w", ErrUnassessable, err)
			}
		}
		if c < 0 {
			// Every later event is higher still, so the state is settled. A
			// fix above an affected version is the version to upgrade to.
			if affected && e.kind == kindFixed {
				return true, e.raw, nil
			}
			break
		}
		switch e.kind {
		case kindIntroduced:
			affected = true
		case kindFixed:
			affected = false
		case kindLastAffected:
			if c > 0 {
				affected = false
			}
		}
	}
	return affected, "", nil
}
