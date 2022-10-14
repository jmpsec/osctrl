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
		fmt.Println("Environment is required")
		os.Exit(1)
	}
	// Retrieve data
	var qs []queries.DistributedQuery
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return err
		}
		qs, err = queriesmgr.GetQueries(target, e.ID)
		if err != nil {
			return err
		}
	} else if apiFlag {
		qs, err = osctrlAPI.GetQueries(env)
		if err != nil {
			return err
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
	if jsonFlag {
		jsonRaw, err := json.Marshal(qs)
		if err != nil {
			return err
		}
		fmt.Println(string(jsonRaw))
	} else if csvFlag {
		data := queriesToData(qs, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return err
		}
	} else if prettyFlag {
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

func deleteQuery(c *cli.Context) error {
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

func runQuery(c *cli.Context) error {
	// Get values from flags
	query := c.String("query")
	if query == "" {
		fmt.Println("Query is required")
		os.Exit(1)
	}
	env := c.String("env")
	if env == "" {
		fmt.Println("Environment is required")
		os.Exit(1)
	}
	uuid := c.String("uuid")
	if uuid == "" {
		fmt.Println("UUID is required")
		os.Exit(1)
	}
	hidden := c.Bool("hidden")
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return err
		}
		queryName := queries.GenQueryName()
		newQuery := queries.DistributedQuery{
			Query:         query,
			Name:          queryName,
			Creator:       appName,
			Expected:      0,
			Executions:    0,
			Active:        true,
			Completed:     false,
			Deleted:       false,
			Hidden:        hidden,
			Type:          queries.StandardQueryType,
			EnvironmentID: e.ID,
		}
		if err := queriesmgr.Create(newQuery); err != nil {
			return err
		}
		if (uuid != "") && nodesmgr.CheckByUUID(uuid) {
			if err := queriesmgr.CreateTarget(queryName, queries.QueryTargetUUID, uuid); err != nil {
				return err
			}
		}
		if err := queriesmgr.SetExpected(queryName, 1, e.ID); err != nil {
			return err
		}
		return nil
	} else if apiFlag {
		q, err := osctrlAPI.RunQuery(env, uuid, query, hidden)
		if err != nil {
			return err
		}
		fmt.Printf("✅ Query %s created successfully", q.Name)
	}
	return nil
}
