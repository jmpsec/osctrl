package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/jmpsec/osctrl/carves"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
)

// Helper function to convert a slice of nodes into the data expected for output
func carvesToData(cs []carves.CarvedFile, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	for _, c := range cs {
		data = append(data, carveToData(c, nil)...)
	}
	return data
}

func carveToData(c carves.CarvedFile, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	_c := []string{
		c.QueryName,
		c.Environment,
		c.Path,
		strconv.Itoa(c.CarveSize) + " / " + strconv.Itoa(c.BlockSize),
		strconv.Itoa(c.CompletedBlocks) + " / " + strconv.Itoa(c.TotalBlocks),
		c.Status,
		c.Carver,
		stringifyBool(c.Archived),
		c.ArchivePath,
	}
	data = append(data, _c)
	return data
}

func listCarves(c *cli.Context) error {
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
	env := c.String("env")
	if env == "" {
		fmt.Println("Environment is required")
		os.Exit(1)
	}
	// Retrieve data
	var cs []carves.CarvedFile
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return err
		}
		cs, err = filecarves.GetByEnv(e.ID)
		if err != nil {
			return err
		}
	} else if apiFlag {
		cs, err = osctrlAPI.GetCarves(env)
		if err != nil {
			return err
		}
	}
	header := []string{
		"QueryName",
		"Environment",
		"Path",
		"Block/Total Size",
		"Completed/Total Blocks",
		"Status",
		"Carver",
		"Archived",
		"ArchivePath",
	}
	// Prepare output
	if jsonFlag {
		jsonRaw, err := json.Marshal(cs)
		if err != nil {
			return err
		}
		fmt.Println(string(jsonRaw))
	} else if csvFlag {
		data := carvesToData(cs, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return err
		}
	} else if prettyFlag {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(header)
		if len(cs) > 0 {
			fmt.Printf("Existing %s queries (%d):\n", target, len(cs))
			data := carvesToData(cs, nil)
			table.AppendBulk(data)
		} else {
			fmt.Printf("No %s nodes\n", target)
		}
		table.Render()
	}
	return nil
}

func completeCarve(c *cli.Context) error {
	// Get values from flags
	name := c.String("name")
	if name == "" {
		fmt.Println("Query name is required")
		os.Exit(1)
	}
	env := c.String("env")
	if env == "" {
		fmt.Println("Environment is required")
		os.Exit(1)
	}
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return err
		}
		return queriesmgr.Complete(name, e.ID)
	} else if apiFlag {
		return osctrlAPI.CompleteQuery(env, name)
	}
	return nil
}

func deleteCarve(c *cli.Context) error {
	// Get values from flags
	name := c.String("name")
	if name == "" {
		fmt.Println("Query name is required")
		os.Exit(1)
	}
	env := c.String("env")
	if env == "" {
		fmt.Println("Environment is required")
		os.Exit(1)
	}
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return err
		}
		return queriesmgr.Delete(name, e.ID)
	} else if apiFlag {
		return osctrlAPI.DeleteQuery(env, name)
	}
	return nil
}
