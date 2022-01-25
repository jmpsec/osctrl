package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/jmpsec/osctrl/settings"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
)

func listConfiguration(c *cli.Context) error {
	values, err := settingsmgr.RetrieveAllValues()
	if err != nil {
		return err
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{
		"Name",
		"Service",
		"Type",
		"String",
		"Integer",
		"Boolean",
		"Info",
	})
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
		table.AppendBulk(data)
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
		fmt.Println("name is required")
		os.Exit(1)
	}
	service := c.String("service")
	if service == "" {
		fmt.Println("service is required")
		os.Exit(1)
	}
	typeValue := c.String("type")
	if typeValue == "" {
		fmt.Println("type is required")
		os.Exit(1)
	}
	values := make(map[string]interface{})
	values[settings.TypeString] = c.String("string")
	values[settings.TypeInteger] = c.Int64("integer")
	values[settings.TypeBoolean] = c.Bool("boolean")
	return settingsmgr.NewValue(service, name, typeValue, values)
}

func updateSetting(c *cli.Context) error {
	// Get values from flags
	name := c.String("name")
	if name == "" {
		fmt.Println("name is required")
		os.Exit(1)
	}
	service := c.String("service")
	if service == "" {
		fmt.Println("service is required")
		os.Exit(1)
	}
	typeValue := c.String("type")
	if typeValue == "" {
		fmt.Println("type is required")
		os.Exit(1)
	}
	info := c.String("info")
	var err error
	switch typeValue {
	case settings.TypeInteger:
		err = settingsmgr.SetInteger(c.Int64("integer"), service, name)
	case settings.TypeBoolean:
		err = settingsmgr.SetBoolean(c.Bool("true"), service, name)
	case settings.TypeString:
		err = settingsmgr.SetString(c.String("string"), service, name, false)
	}
	if err != nil {
		return err
	}
	if info != "" {
		err = settingsmgr.SetInfo(info, service, name)
	}
	return err
}

func deleteSetting(c *cli.Context) error {
	// Get values from flags
	name := c.String("name")
	if name == "" {
		fmt.Println("name is required")
		os.Exit(1)
	}
	service := c.String("service")
	if service == "" {
		fmt.Println("service is required")
		os.Exit(1)
	}
	return settingsmgr.DeleteValue(service, name)
}
