package main

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
)

const (
	// Length to truncate strings
	lengthToTruncate = 10
)

func addUser(c *cli.Context) error {
	// Get values from flags
	username := c.String("username")
	if username == "" {
		fmt.Println("username is required")
		os.Exit(1)
	}
	defaultEnv := c.String("environment")
	if defaultEnv == "" {
		fmt.Println("environment is required")
		os.Exit(1)
	}
	env, err := envs.Get(defaultEnv)
	if err != nil {
		return err
	}
	password := c.String("password")
	email := c.String("email")
	fullname := c.String("fullname")
	admin := c.Bool("admin")
	user, err := adminUsers.New(username, password, email, fullname, env.UUID, admin)
	if err != nil {
		return err
	}
	// Create user
	if err := adminUsers.Create(user); err != nil {
		return err
	}
	// Assign permissions to user
	access := adminUsers.GenEnvUserAccess([]string{env.UUID}, true, (admin == true), (admin == true), (admin == true))
	perms := adminUsers.GenPermissions(username, appName, access)
	if err := adminUsers.CreatePermissions(perms); err != nil {
		return err
	}
	fmt.Printf("Created user %s successfully", username)
	return nil
}

func editUser(c *cli.Context) error {
	// Get values from flags
	username := c.String("username")
	if username == "" {
		fmt.Println("username is required")
		os.Exit(1)
	}
	password := c.String("password")
	if password != "" {
		if err := adminUsers.ChangePassword(username, password); err != nil {
			return err
		}
	}
	email := c.String("email")
	if email != "" {
		if err := adminUsers.ChangeEmail(username, email); err != nil {
			return err
		}
	}
	fullname := c.String("fullname")
	if fullname != "" {
		if err := adminUsers.ChangeFullname(username, fullname); err != nil {
			return err
		}
	}
	admin := c.Bool("admin")
	if admin {
		if err := adminUsers.ChangeAdmin(username, admin); err != nil {
			return err
		}
	}
	notAdmin := c.Bool("non-admin")
	if notAdmin {
		if err := adminUsers.ChangeAdmin(username, admin); err != nil {
			return err
		}
	}
	defaultEnv := c.String("environment")
	if defaultEnv != "" {
		if err := adminUsers.ChangeDefaultEnv(username, defaultEnv); err != nil {
			return err
		}
	}
	fmt.Printf("Edited user %s successfully", username)
	return nil
}

func deleteUser(c *cli.Context) error {
	// Get values from flags
	username := c.String("username")
	if username == "" {
		fmt.Println("username is required")
		os.Exit(1)
	}
	return adminUsers.Delete(username)
}

func listUsers(c *cli.Context) error {
	users, err := adminUsers.All()
	if err != nil {
		return err
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{
		"Username",
		"Fullname",
		"PassHash",
		"Admin?",
		"Default Environment",
		"Last IPAddress",
		"Last UserAgent",
		"Permissions",
	})
	if len(users) > 0 {
		data := [][]string{}
		for _, u := range users {
			uAccess, err := adminUsers.GetAccess(u.Username)
			if err != nil {
				return err
			}
			u := []string{
				u.Username,
				u.Fullname,
				truncateString(u.PassHash, lengthToTruncate),
				stringifyBool(u.Admin),
				u.DefaultEnv,
				u.LastIPAddress,
				u.LastUserAgent,
				stringifyUserAccess(uAccess),
			}
			data = append(data, u)
		}
		table.AppendBulk(data)
		table.Render()
	} else {
		fmt.Printf("No users\n")
	}
	return nil
}

func permissionsUser(c *cli.Context) error {
	// Get values from flags
	username := c.String("username")
	if username == "" {
		fmt.Println("username is required")
		os.Exit(1)
	}
	show := c.Bool("show")
	// Show is just display user existing permissions and return
	if show {
		existingAccess, err := adminUsers.GetAccess(username)
		if err != nil {
			return err
		}
		table := tablewriter.NewWriter(os.Stdout)
		table.SetHeader([]string{
			"Username",
			"Environment",
			"User access",
			"Admin access",
			"Query access",
			"Carve access",
		})
		data := [][]string{}
		for e, p := range existingAccess {
			env, err := envs.Get(e)
			if err != nil {
				return err
			}
			r := []string{
				username,
				fmt.Sprintf("%s (%s)", e, env.Name),
				stringifyBool(p.User),
				stringifyBool(p.Admin),
				stringifyBool(p.Query),
				stringifyBool(p.Carve),
			}
			data = append(data, r)
		}
		table.AppendBulk(data)
		table.Render()
		return nil
	}
	envName := c.String("environment")
	if envName == "" {
		fmt.Println("environment is required")
		os.Exit(1)
	}
	env, err := envs.Get(envName)
	if err != nil {
		return err
	}
	admin := c.Bool("admin")
	user := c.Bool("user")
	carve := c.Bool("carve")
	query := c.Bool("query")
	// If admin, then all permissions follow
	if admin {
		user = true
		query = true
		carve = true
	}
	// Reset permissions to regular user access
	reset := c.Bool("reset")
	if reset {
		if err := adminUsers.DeletePermissions(username, env.UUID); err != nil {
			return err
		}
		access := adminUsers.GenEnvUserAccess([]string{env.UUID}, true, query, carve, admin)
		perms := adminUsers.GenPermissions(username, appName, access)
		if err := adminUsers.CreatePermissions(perms); err != nil {
			return err
		}
		fmt.Printf("Permissions reset for user %s successfully", username)
	} else {
		if user {
			if err := adminUsers.SetEnvUser(username, env.UUID, user); err != nil {
				return err
			}
		}
		if admin {
			if err := adminUsers.SetEnvAdmin(username, env.UUID, admin); err != nil {
				return err
			}
		}
		if carve {
			if err := adminUsers.SetEnvCarve(username, env.UUID, carve); err != nil {
				return err
			}
		}
		if query {
			if err := adminUsers.SetEnvQuery(username, env.UUID, query); err != nil {
				return err
			}
		}
		fmt.Printf("Permissions changed for user %s successfully", username)
	}
	return nil
}
