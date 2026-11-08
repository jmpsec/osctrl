package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v3"
)

func sensitivePathsEnvFlag(cmd *cli.Command) (string, error) {
	env := cmd.String("environment")
	if env == "" {
		return "", fmt.Errorf("environment is required")
	}
	return env, nil
}

func listSensitivePaths(ctx context.Context, cmd *cli.Command) error {
	env, err := sensitivePathsEnvFlag(cmd)
	if err != nil {
		return err
	}
	var rows []environments.SensitivePath
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("error env get - %w", err)
		}
		rows, err = envs.SensitivePaths(e.ID)
		if err != nil {
			return err
		}
	} else if apiFlag {
		rows, err = osctrlAPI.ListSensitivePaths(env)
		if err != nil {
			return err
		}
	}
	header := []string{"ID", "Path", "CreatedBy", "Created"}
	data := make([][]string, 0, len(rows))
	for _, r := range rows {
		data = append(data, []string{strconv.FormatUint(uint64(r.ID), 10), r.Path, r.CreatedBy, r.CreatedAt.String()})
	}
	switch formatFlag {
	case jsonFormat:
		if rows == nil {
			rows = []environments.SensitivePath{}
		}
		jsonRaw, err := json.Marshal(rows)
		if err != nil {
			return fmt.Errorf("error marshaling - %w", err)
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		if err := csv.NewWriter(os.Stdout).WriteAll(append([][]string{header}, data...)); err != nil {
			return fmt.Errorf("error writing csv - %w", err)
		}
	case prettyFormat:
		if len(rows) == 0 {
			fmt.Println("No sensitive paths")
			return nil
		}
		fmt.Printf("Sensitive paths (%d):\n", len(rows))
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		if err := table.Bulk(data); err != nil {
			return fmt.Errorf("error bulk table - %w", err)
		}
		return table.Render()
	}
	return nil
}

func addSensitivePath(ctx context.Context, cmd *cli.Command) error {
	env, err := sensitivePathsEnvFlag(cmd)
	if err != nil {
		return err
	}
	p := cmd.String("path")
	if p == "" {
		return fmt.Errorf("path is required")
	}
	var row environments.SensitivePath
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("error env get - %w", err)
		}
		row, err = envs.AddSensitivePath(e.ID, p, getShellUsername())
		if err != nil {
			return err
		}
		auditlogsmgr.EnvAction(getShellUsername(), "sensitive path add "+row.Path, "CLI", e.ID)
	} else if apiFlag {
		row, err = osctrlAPI.AddSensitivePath(env, p)
		if err != nil {
			return err
		}
	}
	if !silentFlag {
		fmt.Printf("✅ sensitive path %s added (id %d)\n", row.Path, row.ID)
	}
	return nil
}

func removeSensitivePath(ctx context.Context, cmd *cli.Command) error {
	env, err := sensitivePathsEnvFlag(cmd)
	if err != nil {
		return err
	}
	id := cmd.Uint("id")
	if id == 0 {
		return fmt.Errorf("id is required")
	}
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("error env get - %w", err)
		}
		row, err := envs.SensitivePath(e.ID, id)
		if err != nil {
			return fmt.Errorf("sensitive path %d: %w", id, err)
		}
		if err := envs.DeleteSensitivePath(e.ID, id); err != nil {
			return err
		}
		auditlogsmgr.EnvAction(getShellUsername(), "sensitive path remove "+row.Path, "CLI", e.ID)
	} else if apiFlag {
		if err := osctrlAPI.DeleteSensitivePath(env, id); err != nil {
			return err
		}
	}
	if !silentFlag {
		fmt.Printf("✅ sensitive path %d removed\n", id)
	}
	return nil
}
