package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
)

func listConfiguration(c *cli.Context) error {
	values, err := settingsmgr.RetrieveAllValues()
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
		table.Bulk(data)
		table.Render()
	} else {
		fmt.Printf("No configuration values\n")
	}
	return nil
}

func addSetting(c *cli.Context) error {
	// Get values from flags
	name := c.String("name")
	if name == "" {
		fmt.Println("❌ name is required")
		os.Exit(1)
	}
	service := c.String("service")
	if service == "" {
		fmt.Println("❌ service is required")
		os.Exit(1)
	}
	typeValue := c.String("type")
	if typeValue == "" {
		fmt.Println("❌ type is required")
		os.Exit(1)
	}
	switch typeValue {
	case settings.TypeString:
		return settingsmgr.NewStringValue(service, name, c.String("string"), settings.NoEnvironmentID)
	case settings.TypeInteger:
		return settingsmgr.NewIntegerValue(service, name, c.Int64("integer"), settings.NoEnvironmentID)
	case settings.TypeBoolean:
		return settingsmgr.NewBooleanValue(service, name, c.Bool("boolean"), settings.NoEnvironmentID)
	}
	return nil
}

func updateSetting(c *cli.Context) error {
	// Get values from flags
	name := c.String("name")
	if name == "" {
		fmt.Println("❌ name is required")
		os.Exit(1)
	}
	service := c.String("service")
	if service == "" {
		fmt.Println("❌ service is required")
		os.Exit(1)
	}
	typeValue := c.String("type")
	if typeValue == "" {
		fmt.Println("❌ type is required")
		os.Exit(1)
	}
	info := c.String("info")
	var err error
	switch typeValue {
	case settings.TypeInteger:
		err = settingsmgr.SetInteger(c.Int64("integer"), service, name, settings.NoEnvironmentID)
	case settings.TypeBoolean:
		err = settingsmgr.SetBoolean(c.Bool("true"), service, name, settings.NoEnvironmentID)
	case settings.TypeString:
		err = settingsmgr.SetString(c.String("string"), service, name, false, settings.NoEnvironmentID)
	}
	if err != nil {
		return fmt.Errorf("error set type - %w", err)
	}
	if info != "" {
		err = settingsmgr.SetInfo(info, service, name, settings.NoEnvironmentID)
	}
	if err != nil {
		return fmt.Errorf("error set info - %w", err)
	}
	if !silentFlag {
		fmt.Println("✅ setting deleted successfully")
	}
	return nil
}

func deleteSetting(c *cli.Context) error {
	// Get values from flags
	name := c.String("name")
	if name == "" {
		fmt.Println("❌ name is required")
		os.Exit(1)
	}
	service := c.String("service")
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
