package main

import (
	"fmt"
	"os"

	"github.com/urfave/cli"
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
	if len(users) > 0 {
		fmt.Printf("Existing users:\n")
		for _, u := range users {
			fmt.Printf("  Username: %s\n", u.Username)
			fmt.Printf("  Fullname: %s\n", u.Fullname)
			fmt.Printf("  Hashed Password: %s\n", u.PassHash)
			fmt.Printf("  Admin? %v\n", u.Admin)
			fmt.Printf("  CSRF: %s\n", u.CSRF)
			fmt.Printf("  Cookie: %s\n", u.Cookie)
			fmt.Printf("  IPAddress: %s\n", u.IPAddress)
			fmt.Printf("  UserAgent: %s\n", u.UserAgent)
			fmt.Println()
		}
	} else {
		fmt.Printf("No users\n")
	}
	return nil
}
