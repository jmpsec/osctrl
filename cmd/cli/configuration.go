package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

func listConfiguration(c *cli.Context) error {
	values, err := config.RetrieveAllValues()
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
