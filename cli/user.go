package main

import (
	"fmt"
	"os"

	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
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
	password := c.String("password")
	email := c.String("email")
	fullname := c.String("fullname")
	admin := c.Bool("admin")
	user, err := adminUsers.New(username, password, email, fullname, admin)
	if err != nil {
		return err
	}
	if err := adminUsers.Create(user); err != nil {
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
		"Last IPAddress",
		"Last UserAgent",
	})
	if len(users) > 0 {
		data := [][]string{}
		for _, u := range users {
			u := []string{
				u.Username,
				u.Fullname,
				truncateString(u.PassHash, lengthToTruncate),
				stringifyBool(u.Admin),
				u.LastIPAddress,
				u.LastUserAgent,
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
