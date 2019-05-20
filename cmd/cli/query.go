package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

func listQueries(c *cli.Context) error {
	// Get values from flags
	target := "all"
	if c.Bool("all") {
		target = "all"
	}
	if c.Bool("active") {
		target = "active"
	}
	if c.Bool("completed") {
		target = "completed"
	}
	if c.Bool("deleted") {
		target = "deleted"
	}
	qs, err := queriesmgr.Gets(target)
	if err != nil {
		return err
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{
		"Name",
		"Creator",
		"Query",
		"Type",
		"Executions",
		"Errors",
		"Active",
		"Completed",
		"Deleted",
	})
	if len(qs) > 0 {
		data := [][]string{}
		fmt.Printf("Existing %s queries (%d):\n", target, len(qs))
		for _, q := range qs {
			_q := []string{
				q.Name,
				q.Creator,
				q.Query,
				q.Type,
				strconv.Itoa(q.Executions),
				strconv.Itoa(q.Errors),
				stringifyBool(q.Active),
				stringifyBool(q.Completed),
				stringifyBool(q.Deleted),
			}
			data = append(data, _q)
		}
		table.AppendBulk(data)
		table.Render()
	} else {
		fmt.Printf("No queries\n")
	}
	return nil
}
