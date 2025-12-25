package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/handlers"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v3"
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
		stringifyBool(q.Expired),
		q.Expiration.String(),
	}
	data = append(data, _q)
	return data
}

func listQueries(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	target := "all"
	if cmd.Bool("all") {
		target = "all"
	}
	if cmd.Bool("active") {
		target = "active"
	}
	if cmd.Bool("completed") {
		target = "completed"
	}
	if cmd.Bool("deleted") {
		target = "deleted"
	}
	if cmd.Bool("hidden") {
		target = "hidden"
	}
	if cmd.Bool("expired") {
		target = "expired"
	}
	env := cmd.String("env")
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
		qs, err = queriesmgr.GetQueries(target, e.ID)
		if err != nil {
			return fmt.Errorf("❌ error get queries - %w", err)
		}
	} else if apiFlag {
		qs, err = osctrlAPI.GetQueries(target, env)
		if err != nil {
			return fmt.Errorf("❌ error get queries - %w", err)
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
			fmt.Printf("Existing %s queries (%d):\n", target, len(qs))
			data := queriesToData(qs, nil)
			if err := table.Bulk(data); err != nil {
				return fmt.Errorf("❌ error bulk table - %w", err)
			}
		} else {
			fmt.Printf("No %s queries\n", target)
		}
		if err := table.Render(); err != nil {
			return fmt.Errorf("❌ error rendering table - %w", err)
		}
	}
	return nil
}

func completeQuery(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	name := cmd.String("name")
	if name == "" {
		fmt.Println("❌ query name is required")
		os.Exit(1)
	}
	env := cmd.String("env")
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
			return fmt.Errorf("❌ error completing query - %w", err)
		}
		// Audit log
		auditlogsmgr.QueryAction(getShellUsername(), "complete query "+name, "CLI", e.ID)
	} else if apiFlag {
		_, err := osctrlAPI.CompleteQuery(env, name)
		if err != nil {
			return fmt.Errorf("❌ error completing query - %w", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ query %s completed successfully\n", name)
	}
	return nil
}

func deleteQuery(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	name := cmd.String("name")
	if name == "" {
		fmt.Println("❌ query name is required")
		os.Exit(1)
	}
	env := cmd.String("env")
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
			return fmt.Errorf("❌ %w", err)
		}
		// Audit log
		auditlogsmgr.QueryAction(getShellUsername(), "delete query "+name, "CLI", e.ID)
	} else if apiFlag {
		_, err := osctrlAPI.DeleteQuery(env, name)
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ query %s deleted successfully\n", name)
	}
	return nil
}

func expireQuery(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	name := cmd.String("name")
	if name == "" {
		fmt.Println("❌ query name is required")
		os.Exit(1)
	}
	env := cmd.String("env")
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
			return fmt.Errorf("❌ error expiring query - %w", err)
		}
		// Audit log
		auditlogsmgr.QueryAction(getShellUsername(), "expire query "+name, "CLI", e.ID)
	} else if apiFlag {
		_, err := osctrlAPI.ExpireQuery(env, name)
		if err != nil {
			return fmt.Errorf("❌ error expiring query - %w", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ query %s expired successfully\n", name)
	}
	return nil
}

func runQuery(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	query := cmd.String("query")
	if query == "" {
		fmt.Println("❌ query is required")
		os.Exit(1)
	}
	env := cmd.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	uuidStr := cmd.String("uuid")
	if uuidStr == "" {
		fmt.Println("❌ UUID is required")
		os.Exit(1)
	}
	uuidList := []string{uuidStr}
	if strings.Contains(uuidStr, ",") {
		uuidList = strings.Split(uuidStr, ",")
	}
	platformStr := cmd.String("platform")
	platformList := []string{platformStr}
	if strings.Contains(platformStr, ",") {
		platformList = strings.Split(platformStr, ",")
	}
	hostStr := cmd.String("host")
	hostList := []string{hostStr}
	if strings.Contains(hostStr, ",") {
		hostList = strings.Split(hostStr, ",")
	}
	tagStr := cmd.String("tag")
	tagList := []string{tagStr}
	if strings.Contains(tagStr, ",") {
		tagList = strings.Split(tagStr, ",")
	}
	expHours := cmd.Int("expiration")
	hidden := cmd.Bool("hidden")
	queryName := queries.GenQueryName()
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("❌ error env get - %w", err)
		}
		expTime := queries.QueryExpiration(expHours)
		if expHours == 0 {
			expTime = time.Time{}
		}
		newQuery := queries.DistributedQuery{
			Query:         query,
			Name:          queryName,
			Creator:       appName,
			Active:        true,
			Expiration:    expTime,
			Hidden:        hidden,
			Type:          queries.StandardQueryType,
			EnvironmentID: e.ID,
		}
		if err := queriesmgr.Create(&newQuery); err != nil {
			return fmt.Errorf("❌ error query create - %w", err)
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
		if err := queriesmgr.SetExpected(queryName, len(targetNodesID), e.ID); err != nil {
			return fmt.Errorf("❌ error set expected - %w", err)
		}
		// Audit log
		auditlogsmgr.NewQuery(getShellUsername(), query, "CLI", e.ID)
	} else if apiFlag {
		q, err := osctrlAPI.RunQuery(env, query, uuidList, hostList, platformList, tagList, hidden, expHours)
		if err != nil {
			return fmt.Errorf("❌ error run query - %w", err)
		}
		queryName = q.Name
	}
	if !silentFlag {
		fmt.Printf("✅ query %s created successfully\n", queryName)
	}
	return nil
}
