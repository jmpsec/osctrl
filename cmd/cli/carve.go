package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/handlers"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
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
	switch formatFlag {
	case jsonFormat:
		jsonRaw, err := json.Marshal(cs)
		if err != nil {
			return err
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		data := carvesToData(cs, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return err
		}
	case prettyFormat:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		if len(cs) > 0 {
			fmt.Printf("Existing carves (%d):\n", len(cs))
			data := carvesToData(cs, nil)
			table.Bulk(data)
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
			return fmt.Errorf("❌ error env get - %w", err)
		}
		qs, err = queriesmgr.GetCarves(target, e.ID)
		if err != nil {
			return fmt.Errorf("❌ error get carve queries - %w", err)
		}
	} else if apiFlag {
		qs, err = osctrlAPI.GetCarveQueries(target, env)
		if err != nil {
			return fmt.Errorf("❌ error get carve queries - %w", err)
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
	switch formatFlag {
	case jsonFormat:
		jsonRaw, err := json.Marshal(qs)
		if err != nil {
			return fmt.Errorf("❌ error json marshal - %w", err)
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		data := queriesToData(qs, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("❌ error csv writeall - %w", err)
		}
	case prettyFormat:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		if len(qs) > 0 {
			fmt.Printf("Existing %s carve queries (%d):\n", target, len(qs))
			data := queriesToData(qs, nil)
			table.Bulk(data)
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
			return fmt.Errorf("❌ error env get - %w", err)
		}
		if err := queriesmgr.Complete(name, e.ID); err != nil {
			return fmt.Errorf("❌ error completing carve - %w", err)
		}
	} else if apiFlag {
		_, err := osctrlAPI.CompleteQuery(env, name)
		if err != nil {
			return fmt.Errorf("❌ error completing carve - %w", err)
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
			return fmt.Errorf("❌ error env get - %w", err)
		}
		if err := queriesmgr.Delete(name, e.ID); err != nil {
			return fmt.Errorf("❌ error deleting carve - %w", err)
		}
	} else if apiFlag {
		_, err := osctrlAPI.DeleteQuery(env, name)
		if err != nil {
			return fmt.Errorf("❌ error deleting carve - %w", err)
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
			return fmt.Errorf("❌ error env get - %w", err)
		}
		if err := queriesmgr.Expire(name, e.ID); err != nil {
			return fmt.Errorf("❌ error expiring carve - %w", err)
		}
	} else if apiFlag {
		_, err := osctrlAPI.ExpireQuery(env, name)
		if err != nil {
			return fmt.Errorf("❌ error expiring carve - %w", err)
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
	uuidStr := c.String("uuid")
	if uuidStr == "" {
		fmt.Println("❌ UUID is required")
		os.Exit(1)
	}
	var uuidList []string
	if strings.Contains(uuidStr, ",") {
		uuidList = strings.Split(uuidStr, ",")
	} else {
		uuidList = []string{uuidStr}
	}
	platformStr := c.String("platform")
	var platformList []string
	if strings.Contains(platformStr, ",") {
		platformList = strings.Split(platformStr, ",")
	} else {
		platformList = []string{platformStr}
	}
	hostStr := c.String("host")
	var hostList []string
	if strings.Contains(hostStr, ",") {
		hostList = strings.Split(hostStr, ",")
	} else {
		hostList = []string{hostStr}
	}
	tagStr := c.String("tag")
	var tagList []string
	if strings.Contains(tagStr, ",") {
		tagList = strings.Split(tagStr, ",")
	} else {
		tagList = []string{tagStr}

	}
	expHours := c.Int("expiration")
	hidden := c.Bool("hidden")
	cName := carves.GenCarveName()
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		expTime := queries.QueryExpiration(expHours)
		if expHours == 0 {
			expTime = time.Time{}
		}
		newQuery := queries.DistributedQuery{
			Query:         carves.GenCarveQuery(path, false),
			Name:          cName,
			Creator:       appName,
			Active:        true,
			Expiration:    expTime,
			Hidden:        hidden,
			Type:          queries.CarveQueryType,
			Path:          path,
			EnvironmentID: e.ID,
		}
		if err := queriesmgr.Create(&newQuery); err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		// Prepare data for the handler code
		data := handlers.ProcessingQuery{
			Envs:          []string{},
			Platforms:     platformList,
			UUIDs:         uuidList,
			Hosts:         hostList,
			Tags:          tagList,
			EnvID:         e.ID,
			InactiveHours: settingsmgr.InactiveHours(settings.NoEnvironmentID),
		}
		manager := handlers.Managers{
			Nodes: nodesmgr,
			Envs:  envs,
			Tags:  tagsmgr,
		}
		targetNodesID, err := handlers.CreateQueryCarve(data, manager, newQuery)
		if err != nil {
			return fmt.Errorf("❌ error creating query carve - %w", err)
		}
		// If the list is empty, we don't need to create node queries
		if len(targetNodesID) != 0 {
			if err := queriesmgr.CreateNodeQueries(targetNodesID, newQuery.ID); err != nil {
				return fmt.Errorf("❌ error creating node queries - %w", err)
			}
		}
		if err := queriesmgr.SetExpected(cName, len(targetNodesID), e.ID); err != nil {
			return fmt.Errorf("❌ error setting expected - %w", err)
		}
	} else if apiFlag {
		c, err := osctrlAPI.RunCarve(env, path, uuidList, hostList, platformList, tagList, hidden, expHours)
		if err != nil {
			return fmt.Errorf("❌ error running carve - %w", err)
		}
		cName = c.Name
	}
	if !silentFlag {
		fmt.Printf("✅ carve %s created successfully\n", cName)
	}
	return nil
}
