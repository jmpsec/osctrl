package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
)

// Helper function to convert a slice of users into the data expected for output
func usersToData(usrs []users.AdminUser, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	for _, u := range usrs {
		data = append(data, userToData(u, nil)...)
	}
	return data
}

func userToData(u users.AdminUser, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	_u := []string{
		u.Username,
		u.Fullname,
		stringifyBool(u.Admin),
		stringifyBool(u.Service),
		u.LastIPAddress,
		u.LastUserAgent,
	}
	data = append(data, _u)
	return data
}

func addUser(c *cli.Context) error {
	// Get values from flags
	username := c.String("username")
	if username == "" {
		fmt.Println("❌ username is required")
		os.Exit(1)
	}
	password := c.String("password")
	email := c.String("email")
	fullname := c.String("fullname")
	admin := c.Bool("admin")
	service := c.Bool("service")
	environment := c.String("environment")
	if dbFlag {
		// Check if user exists
		if adminUsers.Exists(username) {
			return fmt.Errorf("user %s already exists", username)
		}
		// Prepare user
		user, err := adminUsers.New(username, password, email, fullname, admin, service)
		if err != nil {
			return fmt.Errorf("error with new user - %w", err)
		}
		// Create user
		if err := adminUsers.Create(user); err != nil {
			return fmt.Errorf("error creating user - %w", err)
		}
		// Prepare permissions
		accessEnvs := []string{environment}
		if admin {
			accessEnvs, err = envs.UUIDs()
			if err != nil {
				return fmt.Errorf("error getting environments - %w", err)
			}
		}
		access := adminUsers.GenEnvUserAccess(accessEnvs, true, admin, admin, admin)
		perms := adminUsers.GenPermissions(username, username, access)
		if err := adminUsers.CreatePermissions(perms); err != nil {
			return fmt.Errorf("error creating permissions - %w", err)
		}
		// Audit log
		auditlogsmgr.UserAction(getShellUsername(), "add user "+username, "CLI")
	} else if apiFlag {
		if err := osctrlAPI.CreateUser(username, password, email, fullname, environment, admin, service); err != nil {
			return fmt.Errorf("error creating user - %w", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ created user %s successfully\n", username)
	}
	return nil
}

func editUser(c *cli.Context) error {
	// Get values from flags
	username := c.String("username")
	if username == "" {
		fmt.Println("❌ username is required")
		os.Exit(1)
	}
	password := c.String("password")
	email := c.String("email")
	fullname := c.String("fullname")
	admin := c.Bool("admin")
	notAdmin := c.Bool("non-admin")
	service := c.Bool("service")
	nonService := c.Bool("non-service")
	if password != "" {
		if dbFlag {
			if err := adminUsers.ChangePassword(username, password); err != nil {
				return fmt.Errorf("error changing password - %w", err)
			}
		}
	}
	if email != "" {
		if dbFlag {
			if err := adminUsers.ChangeEmail(username, email); err != nil {
				return fmt.Errorf("error changing email - %w", err)
			}
		}
	}
	if fullname != "" {
		if dbFlag {
			if err := adminUsers.ChangeFullname(username, fullname); err != nil {
				return fmt.Errorf("error changing name - %w", err)
			}
		}
	}
	if admin {
		if dbFlag {
			if err := adminUsers.ChangeAdmin(username, admin); err != nil {
				return fmt.Errorf("error changing admin - %w", err)
			}
		}
	}
	if notAdmin {
		if dbFlag {
			if err := adminUsers.ChangeAdmin(username, false); err != nil {
				return fmt.Errorf("error changing non-admin - %w", err)
			}
		}
	}
	if service {
		if dbFlag {
			if err := adminUsers.ChangeService(username, true); err != nil {
				return fmt.Errorf("error changing service - %w", err)
			}
		}
	}
	if nonService {
		if dbFlag {
			if err := adminUsers.ChangeService(username, false); err != nil {
				return fmt.Errorf("error changing service - %w", err)
			}
		}
	}
	if apiFlag {
		u := types.ApiUserRequest{
			Username:   username,
			Password:   password,
			Email:      email,
			Fullname:   fullname,
			Admin:      admin,
			NotAdmin:   notAdmin,
			Service:    service,
			NotService: nonService,
		}
		if err := osctrlAPI.EditUserReq(u); err != nil {
			return fmt.Errorf("error editing user - %w", err)
		}
	}
	// Audit log
	if dbFlag {
		auditlogsmgr.UserAction(getShellUsername(), "edit user "+username, "CLI")
	}
	if !silentFlag {
		fmt.Printf("✅ user %s edited successfully\n", username)
	}
	return nil
}

func deleteUser(c *cli.Context) error {
	// Get values from flags
	username := c.String("username")
	if username == "" {
		fmt.Println("❌ username is required")
		os.Exit(1)
	}
	if dbFlag {
		if err := adminUsers.Delete(username); err != nil {
			return fmt.Errorf("error deleting - %w", err)
		}
		// Delete permissions
		if err := adminUsers.DeleteAllPermissions(username); err != nil {
			return fmt.Errorf("error deleting permissions - %w", err)
		}
		// Audit log
		auditlogsmgr.UserAction(getShellUsername(), "delete user "+username, "CLI")
	} else if apiFlag {
		if err := osctrlAPI.DeleteUser(username); err != nil {
			return fmt.Errorf("error deleting user - %w", err)
		}
	}
	if !silentFlag {
		fmt.Println("✅ user was deleted successfully")
	}
	return nil
}

func listUsers(c *cli.Context) error {
	// Retrieve data
	var usrs []users.AdminUser
	if dbFlag {
		usrs, err = adminUsers.All()
		if err != nil {
			return fmt.Errorf("error getting users - %w", err)
		}
	} else if apiFlag {
		usrs, err = osctrlAPI.GetUsers()
		if err != nil {
			return fmt.Errorf("error getting users - %w", err)
		}
	}
	header := []string{
		"Username",
		"Fullname",
		"Admin?",
		"Service?",
		"Last IPAddress",
		"Last UserAgent",
	}
	// Prepare output
	switch formatFlag {
	case jsonFormat:
		jsonRaw, err := json.Marshal(usrs)
		if err != nil {
			return fmt.Errorf("error serializing - %w", err)
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		data := usersToData(usrs, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error WriteAll - %w", err)
		}
	case prettyFormat:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		if len(usrs) > 0 {
			fmt.Printf("Existing users (%d):\n", len(usrs))
			data := usersToData(usrs, nil)
			table.Bulk(data)
		} else {
			fmt.Println("No users")
		}
		table.Render()
	}
	return nil
}

func showUser(c *cli.Context) error {
	// Get values from flags
	username := c.String("username")
	if username == "" {
		fmt.Println("❌ username is required")
		os.Exit(1)
	}
	// Retrieve data
	var usr users.AdminUser
	if dbFlag {
		usr, err = adminUsers.Get(username)
		if err != nil {
			return fmt.Errorf("error getting user - %w", err)
		}
	} else if apiFlag {
		usr, err = osctrlAPI.GetUser(username)
		if err != nil {
			return fmt.Errorf("error getting user - %w", err)
		}
	}
	header := []string{
		"Username",
		"Fullname",
		"Admin?",
		"Last IPAddress",
		"Last UserAgent",
	}
	// Prepare output
	switch formatFlag {
	case jsonFormat:
		jsonRaw, err := json.Marshal(usr)
		if err != nil {
			return fmt.Errorf("error serializing - %w", err)
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		data := userToData(usr, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error WriteAll - %w", err)
		}
	case prettyFormat:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		data := userToData(usr, nil)
		table.Bulk(data)
		table.Render()
	}
	return nil
}
