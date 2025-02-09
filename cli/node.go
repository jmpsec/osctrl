package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/tags"
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
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	// Retrieve data
	var nds []nodes.OsqueryNode
	if dbFlag {
		nds, err = nodesmgr.Gets(target, settingsmgr.InactiveHours(settings.NoEnvironmentID))
		if err != nil {
			return fmt.Errorf("error getting nodes - %s", err)
		}
	} else if apiFlag {
		nds, err = osctrlAPI.GetNodes(env, target)
		if err != nil {
			return fmt.Errorf("error getting nodes - %s", err)
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
	if formatFlag == jsonFormat {
		jsonRaw, err := json.Marshal(nds)
		if err != nil {
			return fmt.Errorf("error marshaling - %s", err)
		}
		fmt.Println(string(jsonRaw))
	} else if formatFlag == csvFormat {
		data := nodesToData(nds, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error writting csv - %s", err)
		}
	} else if formatFlag == prettyFormat {
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
		fmt.Println("❌ uuid is required")
		os.Exit(1)
	}
	env := c.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	if dbFlag {
		if err := nodesmgr.ArchiveDeleteByUUID(uuid); err != nil {
			return fmt.Errorf("error deleting - %s", err)
		}
	} else if apiFlag {
		if err := osctrlAPI.DeleteNode(env, uuid); err != nil {
			return fmt.Errorf("error deleting node - %s", err)
		}
	}
	if !silentFlag {
		fmt.Println("✅ node was deleted successfully")
	}
	return nil
}

func tagNode(c *cli.Context) error {
	// Get values from flags
	uuid := c.String("uuid")
	if uuid == "" {
		fmt.Println("❌ uuid is required")
		os.Exit(1)
	}
	env := c.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	tag := c.String("tag-value")
	if env == "" {
		fmt.Println("❌ tag is required")
		os.Exit(1)
	}
	tagType := c.String("tag-type")
	tagTypeInt := tags.TagTypeCustom
	switch tagType {
	case "env":
		tagTypeInt = tags.TagTypeEnv
	case "uuid":
		tagTypeInt = tags.TagTypeUUID
	case "localname":
		tagTypeInt = tags.TagTypeLocalname
	}
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("error env get - %s", err)
		}
		n, err := nodesmgr.GetByUUIDEnv(uuid, e.ID)
		if err != nil {
			return fmt.Errorf("error get uuid - %s", err)
		}
		if tagsmgr.Exists(tag) {
			if err := tagsmgr.TagNode(tag, n, appName, false, tagTypeInt); err != nil {
				return fmt.Errorf("error tagging - %s", err)
			}
		}
	} else if apiFlag {
		if err := osctrlAPI.TagNode(env, uuid, tag); err != nil {
			return fmt.Errorf("error tagging node - %s", err)
		}
	}
	if !silentFlag {
		fmt.Println("✅ node was tagged successfully")
	}
	return nil
}

func showNode(c *cli.Context) error {
	// Get values from flags
	uuid := c.String("uuid")
	if uuid == "" {
		fmt.Println("❌ UUID is required")
		os.Exit(1)
	}
	env := c.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	var node nodes.OsqueryNode
	if dbFlag {
		node, err = nodesmgr.GetByUUID(uuid)
		if err != nil {
			return fmt.Errorf("error getting node - %s", err)
		}
	} else if apiFlag {
		node, err = osctrlAPI.GetNode(env, uuid)
		if err != nil {
			return fmt.Errorf("error getting node - %s", err)
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
	if formatFlag == jsonFormat {
		jsonRaw, err := json.Marshal(node)
		if err != nil {
			return fmt.Errorf("error marshaling - %s", err)
		}
		fmt.Println(string(jsonRaw))
	} else if formatFlag == csvFormat {
		data := nodeToData(node, nil)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error writting csv - %s", err)
		}
	} else if formatFlag == prettyFormat {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(header)
		data := nodeToData(node, nil)
		table.AppendBulk(data)
		table.Render()
	}
	return nil
}
