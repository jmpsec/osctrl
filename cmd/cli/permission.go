package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v3"
)

// Helper function to convert user permissions into the data expected for output
func permissionsToData(perms users.UserAccess, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	for e, p := range perms {
		_p := []string{
			e,
			stringifyBool(p.User),
			stringifyBool(p.Admin),
			stringifyBool(p.Query),
			stringifyBool(p.Carve),
		}
		data = append(data, _p)
	}
	return data
}

// Helper function
func accessToData(access users.EnvAccess, env string, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	_p := []string{
		env,
		stringifyBool(access.User),
		stringifyBool(access.Admin),
		stringifyBool(access.Query),
		stringifyBool(access.Carve),
	}
	data = append(data, _p)
	return data
}

func changePermissions(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	username := cmd.String("username")
	if username == "" {
		fmt.Println("❌ username is required")
		os.Exit(1)
	}
	envName := cmd.String("environment")
	if envName == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	admin := cmd.Bool("admin")
	user := cmd.Bool("user")
	carve := cmd.Bool("carve")
	query := cmd.Bool("query")
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return fmt.Errorf("error getting environment - %w", err)
		}
		// If admin, then all permissions follow
		if admin {
			user = true
			query = true
			carve = true
		}
		// Reset permissions to regular user access
		if user {
			if err := adminUsers.SetEnvUser(username, env.UUID, user); err != nil {
				return fmt.Errorf("error setting user - %w", err)
			}
		}
		if admin {
			if err := adminUsers.SetEnvAdmin(username, env.UUID, admin); err != nil {
				return fmt.Errorf("error setting admin - %w", err)
			}
		}
		if carve {
			if err := adminUsers.SetEnvCarve(username, env.UUID, carve); err != nil {
				return fmt.Errorf("error setting carve - %w", err)
			}
		}
		if query {
			if err := adminUsers.SetEnvQuery(username, env.UUID, query); err != nil {
				return fmt.Errorf("error setting query - %w", err)
			}
		}
		// Audit log
		auditlogsmgr.Permissions(getShellUsername(), "changed permissions for user "+username, "CLI", env.ID)
	}
	if !silentFlag {
		fmt.Printf("✅ permissions changed for user %s successfully\n", username)
	}
	return nil
}

func showPermissions(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	username := cmd.String("username")
	if username == "" {
		fmt.Println("❌ username is required")
		os.Exit(1)
	}
	envName := cmd.String("environment")
	if envName == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	// Retrieve data
	var userAccess users.EnvAccess
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return fmt.Errorf("error env get - %w", err)
		}
		// Show is just display user existing permissions and return
		userAccess, err = adminUsers.GetEnvAccess(username, env.UUID)
		if err != nil {
			return fmt.Errorf("error getting access - %w", err)
		}
	}
	header := []string{
		"Environment",
		"User access",
		"Admin access",
		"Query access",
		"Carve access",
	}
	// Prepare output
	switch formatFlag {
	case jsonFormat:
		jsonRaw, err := json.Marshal(userAccess)
		if err != nil {
			return fmt.Errorf("error serializing - %w", err)
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		data := accessToData(userAccess, envName, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error WriteAll - %w", err)
		}
	case prettyFormat:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		data := accessToData(userAccess, envName, nil)
		table.Bulk(data)
		table.Render()
	}
	return nil
}

func resetPermissions(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	username := cmd.String("username")
	if username == "" {
		fmt.Println("❌ username is required")
		os.Exit(1)
	}
	envName := cmd.String("environment")
	if envName == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	admin := cmd.Bool("admin")
	user := cmd.Bool("user")
	carve := cmd.Bool("carve")
	query := cmd.Bool("query")
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		// If admin, then all permissions follow
		if admin {
			user = true
			query = true
			carve = true
		}
		if err := adminUsers.DeleteEnvPermissions(username, env.UUID); err != nil {
			return err
		}
		access := adminUsers.GenEnvUserAccess([]string{env.UUID}, user, query, carve, admin)
		perms := adminUsers.GenPermissions(username, appName, access)
		if err := adminUsers.CreatePermissions(perms); err != nil {
			return err
		}
		// Audit log
		auditlogsmgr.Permissions(getShellUsername(), "reset permissions for user "+username, "CLI", env.ID)
	}
	if !silentFlag {
		fmt.Printf("✅ permissions reset for user %s successfully\n", username)
	}
	return nil
}

func allPermissions(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	username := cmd.String("username")
	if username == "" {
		fmt.Println("❌ username is required")
		os.Exit(1)
	}
	var existingAccess users.UserAccess
	if dbFlag {
		// Show is just display user existing permissions and return
		existingAccess, err = adminUsers.GetAccess(username)
		if err != nil {
			return fmt.Errorf("error getting access - %w", err)
		}
	}
	header := []string{
		"Environment",
		"User access",
		"Admin access",
		"Query access",
		"Carve access",
	}
	// Prepare output
	switch formatFlag {
	case jsonFormat:
		jsonRaw, err := json.Marshal(existingAccess)
		if err != nil {
			return fmt.Errorf("error serializing - %w", err)
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		data := permissionsToData(existingAccess, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error WriteAll - %w", err)
		}
	case prettyFormat:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		data := permissionsToData(existingAccess, nil)
		table.Bulk(data)
		table.Render()
	}
	return nil
}
