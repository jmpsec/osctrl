package main

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v3"
)

func listConfiguration(ctx context.Context, cmd *cli.Command) error {
	var values []settings.SettingValue
	var err error
	if dbFlag {
		values, err = settingsmgr.RetrieveAllValues()
	} else if apiFlag {
		values, err = osctrlAPI.GetSettings()
	}
	if err != nil {
		return err
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.Header("Name", "Service", "Type", "String", "Integer", "Boolean", "Info")
	if len(values) > 0 {
		data := [][]string{}
		for _, v := range values {
			_v := []string{
				v.Name,
				v.Service,
				v.Type,
				v.String,
				strconv.FormatInt(v.Integer, 10),
				stringifyBool(v.Boolean),
				v.Info,
			}
			data = append(data, _v)
		}
		if err := table.Bulk(data); err != nil {
			return fmt.Errorf("error bulk table - %w", err)
		}
		if err := table.Render(); err != nil {
			return fmt.Errorf("error rendering table - %w", err)
		}
	} else {
		fmt.Printf("No configuration values\n")
	}
	return nil
}

func addSetting(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	name := cmd.String("name")
	if name == "" {
		fmt.Println("❌ name is required")
		os.Exit(1)
	}
	service := cmd.String("service")
	if service == "" {
		fmt.Println("❌ service is required")
		os.Exit(1)
	}
	typeValue := cmd.String("type")
	if typeValue == "" {
		fmt.Println("❌ type is required")
		os.Exit(1)
	}
	switch typeValue {
	case settings.TypeString:
		return settingsmgr.NewStringValue(service, name, cmd.String("string"), settings.NoEnvironmentID)
	case settings.TypeInteger:
		return settingsmgr.NewIntegerValue(service, name, cmd.Int64("integer"), settings.NoEnvironmentID)
	case settings.TypeBoolean:
		return settingsmgr.NewBooleanValue(service, name, cmd.Bool("boolean"), settings.NoEnvironmentID)
	}
	return nil
}

func updateSetting(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	name := cmd.String("name")
	if name == "" {
		return fmt.Errorf("name is required")
	}
	service := cmd.String("service")
	if service == "" {
		return fmt.Errorf("service is required")
	}
	typeValue := cmd.String("type")
	if typeValue == "" {
		return fmt.Errorf("type is required")
	}
	info := cmd.String("info")
	if typeValue != settings.TypeInteger && typeValue != settings.TypeBoolean && typeValue != settings.TypeString {
		return fmt.Errorf("unknown type %q (string|boolean|integer)", typeValue)
	}
	if dbFlag {
		// Same checks as the API's SettingPatchHandler: the setting must exist,
		// the type must match the stored one, and range validators apply.
		existing, err := settingsmgr.RetrieveValue(service, name, settings.NoEnvironmentID)
		if err != nil {
			return fmt.Errorf("error set type - setting not found or unreadable - %w", err)
		}
		if existing.Type != typeValue {
			return fmt.Errorf("setting is %s - provide `%s`, not %s", existing.Type, existing.Type, typeValue)
		}
		if typeValue == settings.TypeInteger {
			if err := settings.ValidateIntegerSetting(service, name, cmd.Int64("integer")); err != nil {
				return err
			}
		}
		switch typeValue {
		case settings.TypeInteger:
			err = settingsmgr.SetInteger(cmd.Int64("integer"), service, name, settings.NoEnvironmentID)
		case settings.TypeBoolean:
			err = settingsmgr.SetBoolean(cmd.Bool("true"), service, name, settings.NoEnvironmentID)
		case settings.TypeString:
			err = settingsmgr.SetString(cmd.String("string"), service, name, settings.NoEnvironmentID)
		}
		if err != nil {
			return fmt.Errorf("error set type - %w", err)
		}
		if info != "" {
			if err := settingsmgr.SetInfo(info, service, name, settings.NoEnvironmentID); err != nil {
				return fmt.Errorf("error set info - %w", err)
			}
		}
	} else if apiFlag {
		if info != "" {
			return fmt.Errorf("--info is not supported in API mode")
		}
		req := types.SettingPatchRequest{Type: typeValue}
		switch typeValue {
		case settings.TypeInteger:
			v := cmd.Int64("integer")
			req.Integer = &v
		case settings.TypeBoolean:
			v := cmd.Bool("true")
			req.Boolean = &v
		case settings.TypeString:
			v := cmd.String("string")
			req.String = &v
		}
		if err := osctrlAPI.PatchSetting(service, name, req); err != nil {
			return fmt.Errorf("error set type - %w", err)
		}
	}
	if !silentFlag {
		fmt.Println("✅ setting updated successfully")
	}
	return nil
}

func deleteSetting(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	name := cmd.String("name")
	if name == "" {
		fmt.Println("❌ name is required")
		os.Exit(1)
	}
	service := cmd.String("service")
	if service == "" {
		fmt.Println("❌ service is required")
		os.Exit(1)
	}
	if err := settingsmgr.DeleteValue(service, name, settings.NoEnvironmentID); err != nil {
		return fmt.Errorf("error get queries - %w", err)
	}
	if !silentFlag {
		fmt.Println("✅ setting deleted successfully")
	}
	return nil
}
