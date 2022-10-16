package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/jmpsec/osctrl/carves"
	"github.com/jmpsec/osctrl/queries"
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
		fmt.Println("❌ environment is required")
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
		fmt.Println("❌ carve name is required")
		os.Exit(1)
	}
	env := c.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
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
		fmt.Println("❌ carve name is required")
		os.Exit(1)
	}
	env := c.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
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

func runCarve(c *cli.Context) error {
	// Get values from flags
	path := c.String("path")
	if path == "" {
		fmt.Println("❌ path is required")
		os.Exit(1)
	}
	env := c.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	uuid := c.String("uuid")
	if uuid == "" {
		fmt.Println("❌ UUID is required")
		os.Exit(1)
	}
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return err
		}
		carveName := carves.GenCarveName()
		newQuery := queries.DistributedQuery{
			Query:         carves.GenCarveQuery(path, false),
			Name:          carveName,
			Creator:       appName,
			Expected:      0,
			Executions:    0,
			Active:        true,
			Completed:     false,
			Deleted:       false,
			Type:          queries.CarveQueryType,
			Path:          path,
			EnvironmentID: e.ID,
		}
		if err := queriesmgr.Create(newQuery); err != nil {
			return err
		}
		if (uuid != "") && nodesmgr.CheckByUUID(uuid) {
			if err := queriesmgr.CreateTarget(carveName, queries.QueryTargetUUID, uuid); err != nil {
				return err
			}
		}
		if err := queriesmgr.SetExpected(carveName, 1, e.ID); err != nil {
			return err
		}
		return nil
	} else if apiFlag {
		c, err := osctrlAPI.RunCarve(env, uuid, path)
		if err != nil {
			return err
		}
		if !silentFlag {
			fmt.Printf("✅ carve %s created successfully", c.Name)
		}
	}
	return nil
}
