package santa

import (
	"errors"
	"fmt"
	"strings"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// VoteRuleCreator is the created_by of rules made by votes.
const VoteRuleCreator = "votes"

var (
	// ErrVotingOff is returned when the environment has no vote threshold.
	ErrVotingOff = errors.New("santa: voting is off")
	// ErrKnownBad is returned for a file a rule blocks: votes cannot allow it.
	ErrKnownBad = errors.New("santa: the file is blocked by a rule")
)

// VoteStatus is where a file stands in the environment's vote.
type VoteStatus struct {
	Votes int64 `json:"votes"`
	// Votes that allow the file on each voter's machine; 0 is off
	LocalThreshold uint32 `json:"local_threshold"`
	// Votes that allow the file in the whole environment; 0 is off
	GlobalThreshold uint32 `json:"global_threshold"`
	// Whether the caller has voted for the file
	Voted bool `json:"voted"`
	// What the votes reached for the caller: "" (nothing yet), node or env
	Allowed string `json:"allowed"`
}

// VoteResult is the outcome of Vote.
type VoteResult struct {
	VoteStatus
	// Counted is false when the voter had already voted for the file.
	Counted bool
	// Rules are the allow rules this vote created.
	Rules []Rule
}

// VoteStatus reports the votes for a file and whether voter is among them.
func (m *Manager) VoteStatus(envID uint, sha256, voter string) (VoteStatus, error) {
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	if !hex64.MatchString(sha256) {
		return VoteStatus{}, fmt.Errorf("%w: sha256 must be 64 hex characters", ErrInvalidRequest)
	}
	cfg, err := m.Config(envID)
	if err != nil {
		return VoteStatus{}, err
	}
	return voteStatus(m.DB, cfg, sha256, voter)
}

func voteStatus(db *gorm.DB, cfg EnvConfig, sha256, voter string) (VoteStatus, error) {
	st := VoteStatus{LocalThreshold: cfg.VoteLocalThreshold, GlobalThreshold: cfg.VoteGlobalThreshold}
	const file = "environment_id = ? AND file_sha256 = ?"
	if err := db.Model(&Vote{}).Where(file, cfg.EnvironmentID, sha256).Count(&st.Votes).Error; err != nil {
		return st, err
	}
	var mine int64
	if err := db.Model(&Vote{}).Where(file+" AND voter = ?", cfg.EnvironmentID, sha256, voter).Count(&mine).Error; err != nil {
		return st, err
	}
	st.Voted = mine > 0
	switch {
	case st.GlobalThreshold > 0 && st.Votes >= int64(st.GlobalThreshold):
		st.Allowed = "env"
	case st.Voted && st.LocalThreshold > 0 && st.Votes >= int64(st.LocalThreshold):
		st.Allowed = "node"
	}
	return st, nil
}

// knownBad reports whether votes must not allow the file of ev: Santa blocked
// it for a reason other than being unknown, or a rule that is not an allow rule
// names the file, its team ID, signing ID or CDHash in any scope.
func knownBad(db *gorm.DB, ev Event) (bool, error) {
	if ev.Decision != "BLOCK_UNKNOWN" {
		return true, nil
	}
	match := db.Where("rule_type = ? AND identifier = ?", "BINARY", strings.ToLower(ev.FileSHA256))
	for typ, id := range map[string]string{"TEAMID": strings.ToUpper(ev.TeamID), "SIGNINGID": ev.SigningID, "CDHASH": strings.ToLower(ev.CDHash)} {
		if id != "" {
			match = match.Or("rule_type = ? AND identifier = ?", typ, id)
		}
	}
	var n int64
	err := db.Model(&Rule{}).Where("environment_id = ? AND policy NOT LIKE ?", ev.EnvironmentID, "ALLOWLIST%").Where(match).Count(&n).Error
	return n > 0, err
}

// Vote records voter's vote to allow a file Santa blocked on their machine, as
// CreateRequest requires. A second vote by the same voter changes nothing.
// At the local threshold every voter's machine gets a node allow rule, and
// later voters get theirs as they vote; at the global threshold the file gets
// one environment allow rule.
func (m *Manager) Vote(envID uint, machineID, sha256, voter string) (VoteResult, error) {
	var res VoteResult
	machineID = strings.ToUpper(strings.TrimSpace(machineID))
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	switch {
	case !uuidRe.MatchString(machineID):
		return res, fmt.Errorf("%w: machine_id must be a UUID", ErrInvalidRequest)
	case !hex64.MatchString(sha256):
		return res, fmt.Errorf("%w: sha256 must be 64 hex characters", ErrInvalidRequest)
	case voter == "":
		return res, fmt.Errorf("%w: voter is required", ErrInvalidRequest)
	}
	cfg, err := m.Config(envID)
	if err != nil {
		return res, err
	}
	if cfg.VoteLocalThreshold == 0 && cfg.VoteGlobalThreshold == 0 {
		return res, ErrVotingOff
	}
	evs, _, err := m.Events(envID, 1, 1, EventFilter{MachineID: machineID, Decision: "BLOCK", SHA256: sha256})
	if err != nil {
		return res, err
	}
	if len(evs) == 0 {
		return res, ErrNoBlockedEvent
	}
	// ponytail: votes are never pruned and a lowered threshold only takes effect
	// on the next vote; add expiry or a recount if either matters.
	err = m.DB.Transaction(func(tx *gorm.DB) error {
		bad, err := knownBad(tx, evs[0])
		if err != nil {
			return err
		}
		if bad {
			return ErrKnownBad
		}
		// The unique key makes a repeated or simultaneous vote a no-op.
		ins := tx.Clauses(clause.OnConflict{DoNothing: true}).
			Create(&Vote{EnvironmentID: envID, FileSHA256: sha256, Voter: voter, MachineID: machineID})
		if ins.Error != nil {
			return ins.Error
		}
		if res.VoteStatus, err = voteStatus(tx, cfg, sha256, voter); err != nil {
			return err
		}
		if res.Counted = ins.RowsAffected > 0; !res.Counted {
			return nil
		}
		var targets []string
		switch res.Allowed {
		case "env":
			targets = []string{""}
		case "node":
			targets = []string{machineID}
			// The vote that reaches the threshold also allows the earlier voters.
			if res.Votes == int64(res.LocalThreshold) {
				if err := tx.Model(&Vote{}).Where("environment_id = ? AND file_sha256 = ?", envID, sha256).
					Distinct().Pluck("machine_id", &targets).Error; err != nil {
					return err
				}
			}
		}
		for _, target := range targets {
			rule := Rule{
				EnvironmentID: envID, Identifier: sha256, RuleType: "BINARY", Policy: "ALLOWLIST",
				Scope: res.Allowed, ScopeValue: target, CreatedBy: VoteRuleCreator,
			}
			if err := ValidateRule(&rule); err != nil {
				return err
			}
			rule, created, err := allowRule(tx, rule)
			if err != nil {
				return err
			}
			if created {
				res.Rules = append(res.Rules, rule)
			}
		}
		return nil
	})
	if err != nil {
		return VoteResult{}, err
	}
	return res, nil
}
