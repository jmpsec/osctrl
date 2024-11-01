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
	if formatFlag == jsonFormat {
		jsonRaw, err := json.Marshal(cs)
		if err != nil {
			return err
		}
		fmt.Println(string(jsonRaw))
	} else if formatFlag == csvFormat {
		data := carvesToData(cs, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return err
		}
	} else if formatFlag == prettyFormat {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(header)
		if len(cs) > 0 {
			fmt.Printf("Existing carves (%d):\n", len(cs))
			data := carvesToData(cs, nil)
			table.AppendBulk(data)
		} else {
			fmt.Println("No carves")
		}
		table.Render()
	}
	return nil
}

func listCarveQueries(c *cli.Context) error {
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
	if c.Bool("hidden") {
		target = "hidden"
	}
	if c.Bool("expired") {
		target = "expired"
	}
	env := c.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	// Retrieve data
	var qs []queries.DistributedQuery
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("❌ error env get - %s", err)
		}
		qs, err = queriesmgr.GetCarves(target, e.ID)
		if err != nil {
			return fmt.Errorf("❌ error get carve queries - %s", err)
		}
	} else if apiFlag {
		qs, err = osctrlAPI.GetQueries(target, env)
		if err != nil {
			return fmt.Errorf("❌ error get carve queries - %s", err)
		}
	}
	header := []string{
		"Name",
		"Creator",
		"Query",
		"Type",
		"Executions",
		"Errors",
		"Active",
		"Hidden",
		"Completed",
		"Deleted",
		"Expired",
		"Expiration",
	}
	// Prepare output
	if formatFlag == jsonFormat {
		jsonRaw, err := json.Marshal(qs)
		if err != nil {
			return fmt.Errorf("❌ error json marshal - %s", err)
		}
		fmt.Println(string(jsonRaw))
	} else if formatFlag == csvFormat {
		data := queriesToData(qs, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("❌ error csv writeall - %s", err)
		}
	} else if formatFlag == prettyFormat {
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader(header)
		if len(qs) > 0 {
			fmt.Printf("Existing %s carve queries (%d):\n", target, len(qs))
			data := queriesToData(qs, nil)
			table.AppendBulk(data)
		} else {
			fmt.Printf("No %s carve queries\n", target)
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
			return fmt.Errorf("❌ error env get - %s", err)
		}
		if err := queriesmgr.Complete(name, e.ID); err != nil {
			return fmt.Errorf("❌ error completing carve - %s", err)
		}
	} else if apiFlag {
		_, err := osctrlAPI.CompleteQuery(env, name)
		if err != nil {
			return fmt.Errorf("❌ error completing carve - %s", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ carve %s completed successfully\n", name)
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
			return fmt.Errorf("❌ error env get - %s", err)
		}
		if err := queriesmgr.Delete(name, e.ID); err != nil {
			return fmt.Errorf("❌ error deleting carve - %s", err)
		}
	} else if apiFlag {
		_, err := osctrlAPI.DeleteQuery(env, name)
		if err != nil {
			return fmt.Errorf("❌ error deleting carve - %s", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ carve %s deleted successfully\n", name)
	}
	return nil
}

func expireCarve(c *cli.Context) error {
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
			return fmt.Errorf("❌ error env get - %s", err)
		}
		if err := queriesmgr.Expire(name, e.ID); err != nil {
			return fmt.Errorf("❌ error expiring carve - %s", err)
		}
	} else if apiFlag {
		_, err := osctrlAPI.ExpireQuery(env, name)
		if err != nil {
			return fmt.Errorf("❌ error expiring carve - %s", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ carve %s expired successfully\n", name)
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
	expHours := c.Int("expiration")
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("❌ %s", err)
		}
		carveName := carves.GenCarveName()
		newQuery := queries.DistributedQuery{
			Query:         carves.GenCarveQuery(path, false),
			Name:          carveName,
			Creator:       appName,
			Expected:      0,
			Executions:    0,
			Active:        true,
			Expired:       false,
			Expiration:    queries.QueryExpiration(expHours),
			Completed:     false,
			Deleted:       false,
			Type:          queries.CarveQueryType,
			Path:          path,
			EnvironmentID: e.ID,
		}
		if err := queriesmgr.Create(newQuery); err != nil {
			return fmt.Errorf("❌ %s", err)
		}
		if (uuid != "") && nodesmgr.CheckByUUID(uuid) {
			if err := queriesmgr.CreateTarget(carveName, queries.QueryTargetUUID, uuid); err != nil {
				return fmt.Errorf("❌ error creating target - %s", err)
			}
		}
		if err := queriesmgr.SetExpected(carveName, 1, e.ID); err != nil {
			return fmt.Errorf("❌ error setting expected - %s", err)
		}
		return nil
	} else if apiFlag {
		c, err := osctrlAPI.RunCarve(env, uuid, path, expHours)
		if err != nil {
			return fmt.Errorf("❌ error running carve - %s", err)
		}
		if !silentFlag {
			fmt.Printf("✅ carve %s created successfully\n", c.Name)
		}
	}
	return nil
}
