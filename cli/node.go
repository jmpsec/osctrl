package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jmpsec/osctrl/nodes"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
)

// Helper function to convert a slice of nodes into the data expected for output
func nodesToData(nds []nodes.OsqueryNode, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	for _, n := range nds {
		data = append(data, nodeToData(n, nil)...)
	}
	return data
}

func nodeToData(n nodes.OsqueryNode, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	_n := []string{
		n.Hostname,
		n.UUID,
		n.Platform,
		n.PlatformVersion,
		n.Environment,
		nodeLastSeen(n),
		n.IPAddress,
		n.OsqueryVersion,
	}
	data = append(data, _n)
	return data
}

func listNodes(c *cli.Context) error {
	// Get flag values for this command
	target := "active"
	if c.Bool("all") {
		target = "all"
	}
	if c.Bool("inactive") {
		target = "inactive"
	}
	env := c.String("env")
	if env == "" {
		fmt.Println("Environment is required")
		os.Exit(1)
	}
	// Retrieve data
	var nds []nodes.OsqueryNode
	if dbFlag {
		nds, err = nodesmgr.Gets(target, settingsmgr.InactiveHours())
		if err != nil {
			return err
		}
	} else if apiFlag {
		nds, err = osctrlAPI.GetNodes(env)
		if err != nil {
			return err
		}
	}
	header := []string{
		"Hostname",
		"UUID",
		"Platform",
		"PlatformVersion",
		"Environment",
		"Last Seen",
		"IPAddress",
		"OsqueryVersion",
	}
	// Prepare output
	if jsonFlag {
		jsonRaw, err := json.Marshal(nds)
		if err != nil {
			return err
		}
		fmt.Println(string(jsonRaw))
	} else if csvFlag {
		data := nodesToData(nds, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return err
		}
	} else if prettyFlag {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(header)
		if len(nds) > 0 {
			fmt.Printf("Existing %s nodes (%d):\n", target, len(nds))
			data := nodesToData(nds, nil)
			table.AppendBulk(data)
		} else {
			fmt.Printf("No %s nodes\n", target)
		}
		table.Render()
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
	env := c.String("name")
	if env == "" {
		fmt.Println("Environment is required")
		os.Exit(1)
	}
	if dbFlag {
		if err := nodesmgr.ArchiveDeleteByUUID(uuid); err != nil {
			return err
		}
	} else if apiFlag {

	}
	fmt.Println("✅ Node has been deleted")
	return nil
}

func showNode(c *cli.Context) error {
	// Get values from flags
	uuid := c.String("uuid")
	if uuid == "" {
		fmt.Println("UUID is required")
		os.Exit(1)
	}
	env := c.String("name")
	if env == "" {
		fmt.Println("Environment is required")
		os.Exit(1)
	}
	var node nodes.OsqueryNode
	if dbFlag {
		node, err = nodesmgr.GetByUUID(uuid)
		if err != nil {
			return err
		}
	} else if apiFlag {
		node, err = osctrlAPI.GetNode(env, uuid)
		if err != nil {
			return err
		}
	}
	header := []string{
		"Hostname",
		"UUID",
		"Platform",
		"PlatformVersion",
		"Environment",
		"Last Seen",
		"IPAddress",
		"OsqueryVersion",
	}
	// Prepare output
	if jsonFlag {
		jsonRaw, err := json.Marshal(node)
		if err != nil {
			return err
		}
		fmt.Println(string(jsonRaw))
	} else if csvFlag {
		data := nodeToData(node, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return err
		}
	} else if prettyFlag {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(header)
		data := nodeToData(node, header)
		table.AppendBulk(data)
		table.Render()
	}
	return nil
}
