package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/jmpsec/osctrl/pkg/santa"
	"github.com/urfave/cli/v3"
	"gorm.io/gorm"
)

// santa.go — actions behind the `santa` CLI command group. DB mode mirrors
// cmd/api/handlers/santa.go (same import logic, size limit and audit text);
// API mode calls the REST API.

// santaImportMaxBytes is the import size limit, the same as the API's.
const santaImportMaxBytes = 4 << 20

// The Santa manager migrates the Santa tables, so it is built on first use by
// a santa action and never by the shared wrapper. Cached per DB connection.
var (
	santaMgrConn *gorm.DB
	santaMgr     *santa.Manager
)

func santaDBManager() (*santa.Manager, error) {
	if db == nil || db.Conn == nil {
		return nil, errors.New("database is not initialised")
	}
	if santaMgr == nil || santaMgrConn != db.Conn {
		mgr, err := santa.NewManager(db.Conn)
		if err != nil {
			return nil, fmt.Errorf("error creating santa manager - %w", err)
		}
		santaMgr, santaMgrConn = mgr, db.Conn
	}
	return santaMgr, nil
}

func santaRulesExport(ctx context.Context, cmd *cli.Command) error {
	env := cmd.String("environment")
	if env == "" {
		return errors.New("environment is required")
	}
	var rules []santa.Rule
	if dbFlag {
		mgr, err := santaDBManager()
		if err != nil {
			return err
		}
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("error getting environment - %w", err)
		}
		if rules, err = mgr.Rules(e.ID); err != nil {
			return fmt.Errorf("error listing rules - %w", err)
		}
	} else if apiFlag {
		var err error
		if rules, err = osctrlAPI.GetSantaRules(env); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(santa.ExportRules(rules), "", "  ")
	if err != nil {
		return fmt.Errorf("error marshaling - %w", err)
	}
	raw = append(raw, '\n')
	if file := cmd.String("file"); file != "" {
		if err := os.WriteFile(file, raw, 0o644); err != nil { //nolint:gosec // rules are not secret
			return fmt.Errorf("error writing file - %w", err)
		}
		if !silentFlag {
			fmt.Printf("✅ exported %d rules to %s\n", len(rules), file)
		}
		return nil
	}
	_, err = os.Stdout.Write(raw)
	return err
}

func santaRulesImport(ctx context.Context, cmd *cli.Command) error {
	env, file, dryRun := cmd.String("environment"), cmd.String("file"), cmd.Bool("dry-run")
	if env == "" {
		return errors.New("environment is required")
	}
	if file == "" {
		return errors.New("file is required")
	}
	info, err := os.Stat(file)
	if err != nil {
		return fmt.Errorf("error reading file - %w", err)
	}
	if info.Size() > santaImportMaxBytes {
		return fmt.Errorf("file is larger than the %d MiB import limit", santaImportMaxBytes>>20)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("error reading file - %w", err)
	}
	var specs []santa.RuleSpec
	if err := json.Unmarshal(raw, &specs); err != nil {
		return fmt.Errorf("file must be a JSON list of rules - %w", err)
	}
	var res santa.ImportResult
	if dbFlag {
		mgr, err := santaDBManager()
		if err != nil {
			return err
		}
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("error getting environment - %w", err)
		}
		if res, err = mgr.ImportRules(e.ID, getShellUsername(), specs, !dryRun); err != nil {
			return fmt.Errorf("error importing rules - %w", err)
		}
		if res.Applied {
			auditlogsmgr.EnvAction(getShellUsername(), fmt.Sprintf("santa: import rules new=%d duplicate=%d", res.New, res.Duplicate), "CLI", e.ID)
		}
	} else if apiFlag {
		if res, err = osctrlAPI.ImportSantaRules(env, specs, dryRun); err != nil {
			return err
		}
	}
	if formatFlag == jsonFormat {
		out, err := json.Marshal(res)
		if err != nil {
			return fmt.Errorf("error marshaling - %w", err)
		}
		fmt.Println(string(out))
	} else {
		fmt.Printf("new: %d, duplicate: %d, conflicting: %d, invalid: %d\n", res.New, res.Duplicate, len(res.Conflicts), len(res.Invalid))
		for _, group := range []struct {
			label  string
			issues []santa.ImportIssue
		}{{"conflict", res.Conflicts}, {"invalid", res.Invalid}} {
			for _, i := range group.issues {
				fmt.Printf("%s: rule %d (%s %s): %s\n", group.label, i.Index, i.Rule.RuleType, i.Rule.Identifier, i.Reason)
			}
		}
	}
	// A blocked import fails, dry run included, so it can gate a review pipeline.
	if res.Blocked() {
		return fmt.Errorf("nothing imported: %d conflicting and %d invalid rules", len(res.Conflicts), len(res.Invalid))
	}
	if !silentFlag && formatFlag != jsonFormat {
		if res.Applied {
			fmt.Printf("✅ imported %d rules\n", res.New)
		} else {
			fmt.Println("dry run: nothing imported")
		}
	}
	return nil
}
