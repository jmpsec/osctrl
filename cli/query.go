package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/jmpsec/osctrl/queries"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
)

// Helper function to convert a slice of nodes into the data expected for output
func queriesToData(qs []queries.DistributedQuery, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	for _, q := range qs {
		data = append(data, queryToData(q, nil)...)
	}
	return data
}

func queryToData(q queries.DistributedQuery, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	_q := []string{
		q.Name,
		q.Creator,
		q.Query,
		q.Type,
		strconv.Itoa(q.Executions),
		strconv.Itoa(q.Errors),
		stringifyBool(q.Active),
		stringifyBool(q.Hidden),
		stringifyBool(q.Completed),
		stringifyBool(q.Deleted),
	}
	data = append(data, _q)
	return data
}

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
	if c.Bool("hidden") {
		target = "hidden"
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
		qs, err = queriesmgr.GetQueries(target, e.ID)
		if err != nil {
			return fmt.Errorf("❌ error get queries - %s", err)
		}
	} else if apiFlag {
		qs, err = osctrlAPI.GetQueries(env)
		if err != nil {
			return fmt.Errorf("❌ error get queries - %s", err)
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
			fmt.Printf("Existing %s queries (%d):\n", target, len(qs))
			data := queriesToData(qs, nil)
			table.AppendBulk(data)
		} else {
			fmt.Printf("No %s nodes\n", target)
		}
		table.Render()
	}
	return nil
}

func completeQuery(c *cli.Context) error {
	// Get values from flags
	name := c.String("name")
	if name == "" {
		fmt.Println("❌ query name is required")
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
			return fmt.Errorf("❌ error completing query - %s", err)
		}
	} else if apiFlag {
		_, err := osctrlAPI.CompleteQuery(env, name)
		if err != nil {
			return fmt.Errorf("❌ error completing query - %s", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ query %s completed successfully\n", name)
	}
	return nil
}

func deleteQuery(c *cli.Context) error {
	// Get values from flags
	name := c.String("name")
	if name == "" {
		fmt.Println("❌ query name is required")
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
			return fmt.Errorf("❌ %s", err)
		}
	} else if apiFlag {
		_, err := osctrlAPI.DeleteQuery(env, name)
		if err != nil {
			return fmt.Errorf("❌ %s", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ query %s deleted successfully\n", name)
	}
	return nil
}

func expireQuery(c *cli.Context) error {
	// Get values from flags
	name := c.String("name")
	if name == "" {
		fmt.Println("❌ query name is required")
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
			return fmt.Errorf("❌ error expiring query - %s", err)
		}
	} else if apiFlag {
		_, err := osctrlAPI.ExpireQuery(env, name)
		if err != nil {
			return fmt.Errorf("❌ error expiring query - %s", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ query %s expired successfully\n", name)
	}
	return nil
}

func runQuery(c *cli.Context) error {
	// Get values from flags
	query := c.String("query")
	if query == "" {
		fmt.Println("❌ query is required")
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
	hidden := c.Bool("hidden")
	var queryName string
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("❌ error env get - %s", err)
		}
		queryName = queries.GenQueryName()
		newQuery := queries.DistributedQuery{
			Query:         query,
			Name:          queryName,
			Creator:       appName,
			Expected:      0,
			Executions:    0,
			Active:        true,
			Expired:       false,
			Expiration:    queries.QueryExpiration(expHours),
			Completed:     false,
			Deleted:       false,
			Hidden:        hidden,
			Type:          queries.StandardQueryType,
			EnvironmentID: e.ID,
		}
		if err := queriesmgr.Create(newQuery); err != nil {
			return fmt.Errorf("❌ error query create - %s", err)
		}
		if (uuid != "") && nodesmgr.CheckByUUID(uuid) {
			if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetUUID, uuid); err != nil {
				return fmt.Errorf("❌ error create target - %s", err)
			}
		}
		if err := queriesmgr.SetExpected(queryName, 1, e.ID); err != nil {
			return fmt.Errorf("❌ error set expected - %s", err)
		}
	} else if apiFlag {
		q, err := osctrlAPI.RunQuery(env, uuid, query, hidden, expHours)
		if err != nil {
			return fmt.Errorf("❌ error run query - %s", err)
		}
		queryName = q.Name
	}
	if !silentFlag {
		fmt.Printf("✅ query %s created successfully\n", queryName)
	}
	return nil
}
