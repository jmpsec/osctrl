package main

import (
	"fmt"
	"os"

	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/utils"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
)

func listNodes(c *cli.Context) error {
	// Get values from flags
	target := "active"
	if c.Bool("all") {
		target = "all"
	}
	if c.Bool("inactive") {
		target = "inactive"
	}
	var nds []nodes.OsqueryNode
	if dbFlag {
		nds, err = nodesmgr.Gets(target, settingsmgr.InactiveHours())
		if err != nil {
			return err
		}
	} else if apiFlag {
		nds, err = osctrlAPI.GetNodes()
		if err != nil {
			return err
		}
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{
		"Hostname",
		"UUID",
		"Platform",
		"Environment",
		"Last Status",
		"IPAddress",
		"Version",
	})
	if len(nds) > 0 {
		data := [][]string{}
		fmt.Printf("Existing %s nodes (%d):\n", target, len(nds))
		for _, n := range nds {
			_n := []string{
				n.Hostname,
				n.UUID,
				n.Platform,
				n.Environment,
				utils.PastFutureTimes(n.LastStatus),
				n.IPAddress,
				n.OsqueryVersion,
			}
			data = append(data, _n)
		}
		table.AppendBulk(data)
		table.Render()
	} else {
		fmt.Printf("No nodes\n")
	}
	return nil
}

func deleteNode(c *cli.Context) error {
	// Get values from flags
	uuid := c.String("uuid")
	if uuid == "" {
		fmt.Println("uuid is required")
		os.Exit(1)
	}
	return nodesmgr.ArchiveDeleteByUUID(uuid)
}
