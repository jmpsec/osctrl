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
	fullname := c.String("fullname")
	admin := c.Bool("admin")
	user, err := adminUsers.New(username, password, fullname, admin)
	if err != nil {
		return err
	}
	if err := adminUsers.Create(user); err != nil {
		return err
	}
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
	return adminUsers.ChangePassword(username, password)
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
		"CSRF Token",
		"IPAddress",
		"UserAgent",
	})
	if len(users) > 0 {
		data := [][]string{}
		for _, u := range users {
			u := []string{
				u.Username,
				u.Fullname,
				truncateString(u.PassHash, lengthToTruncate),
				stringifyBool(u.Admin),
				u.CSRF,
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
