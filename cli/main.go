package main

import (
	"fmt"
	"log"
	"os"

	"github.com/jmpsec/osctrl/backend"
	"github.com/jmpsec/osctrl/environments"
	"github.com/jmpsec/osctrl/nodes"
	"github.com/jmpsec/osctrl/queries"
	"github.com/jmpsec/osctrl/settings"
	"github.com/jmpsec/osctrl/tags"
	"github.com/jmpsec/osctrl/users"

	"github.com/jinzhu/gorm"
	"github.com/urfave/cli"
)

const (
	// DB configuration file
	defDBConfigurationFile string = "config/db.json"
	// Project name
	projectName string = "osctrl"
	// Application name
	appName string = projectName + "-cli"
	// Application version
	appVersion string = "0.2.4"
	// Application usage
	appUsage string = "CLI for " + projectName
	// Application description
	appDescription string = appUsage + ", a fast and efficient osquery management"
)

// Global variables
var (
	db           *gorm.DB
	app          *cli.App
	flags        []cli.Flag
	commands     []cli.Command
	dbConfigFile string
	settingsmgr  *settings.Settings
	nodesmgr     *nodes.NodeManager
	queriesmgr   *queries.Queries
	adminUsers   *users.UserManager
	tagsmgr      *tags.TagManager
	envs         *environments.Environment
)

// Initialization code
func init() {
	// Initialize CLI flags
	flags = []cli.Flag{
		cli.StringFlag{
			Name:        "D, db",
			Value:       defDBConfigurationFile,
			Usage:       "Load DB configuration from `FILE`",
			EnvVar:      "DB_CONFIG",
			Destination: &dbConfigFile,
		},
	}
	// Initialize CLI flags commands
	commands = []cli.Command{
		{
			Name:  "user",
			Usage: "Commands for users",
			Subcommands: []cli.Command{
				{
					Name:    "add",
					Aliases: []string{"a"},
					Usage:   "Add a new user",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "username, u",
							Usage: "Username for the new user",
						},
						cli.StringFlag{
							Name:  "password, p",
							Usage: "Password for the new user",
						},
						cli.BoolFlag{
							Name:   "admin, a",
							Hidden: false,
							Usage:  "Make this user an admin",
						},
						cli.StringFlag{
							Name:  "email, e",
							Usage: "Email for the new user",
						},
						cli.StringFlag{
							Name:  "fullname, n",
							Usage: "Full name for the new user",
						},
					},
					Action: cliWrapper(addUser),
				},
				{
					Name:    "edit",
					Aliases: []string{"e"},
					Usage:   "Edit an existing user",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "username, u",
							Usage: "User to be edited",
						},
						cli.StringFlag{
							Name:  "password, p",
							Usage: "New password to be used",
						},
						cli.StringFlag{
							Name:  "email, e",
							Usage: "Email to be used",
						},
						cli.StringFlag{
							Name:  "fullname, n",
							Usage: "Full name to be used",
						},
						cli.BoolFlag{
							Name:   "admin, a",
							Hidden: false,
							Usage:  "Make this user an admin",
						},
						cli.BoolFlag{
							Name:   "non-admin, d",
							Hidden: false,
							Usage:  "Make this user an non-admin",
						},
					},
					Action: cliWrapper(editUser),
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Delete an existing user",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "username, u",
							Usage: "User to be deleted",
						},
					},
					Action: cliWrapper(deleteUser),
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List all existing users",
					Action:  cliWrapper(listUsers),
				},
			},
		},
		{
			Name:    "environment",
			Aliases: []string{"env"},
			Usage:   "Commands for TLS environment",
			Subcommands: []cli.Command{
				{
					Name:    "add",
					Aliases: []string{"a"},
					Usage:   "Add a new TLS environment",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Environment to be added",
						},
						cli.StringFlag{
							Name:  "hostname, host",
							Usage: "Environment host to be added",
						},
						cli.BoolFlag{
							Name:   "debug, d",
							Hidden: false,
							Usage:  "Environment debug capability",
						},
						cli.StringFlag{
							Name:  "certificate, crt",
							Usage: "Certificate file to be read",
						},
					},
					Action: cliWrapper(addEnvironment),
				},
				{
					Name:    "update",
					Aliases: []string{"u"},
					Usage:   "Update an existing TLS environment",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Environment to be updated",
						},
						cli.BoolFlag{
							Name:  "debug, d",
							Usage: "Environment debug capability",
						},
						cli.StringFlag{
							Name:  "hostname, host",
							Usage: "Environment host to be updated",
						},
						cli.IntFlag{
							Name:  "logging, l",
							Value: 0,
							Usage: "Logging interval in seconds",
						},
						cli.IntFlag{
							Name:  "config, c",
							Value: 0,
							Usage: "Config interval in seconds",
						},
						cli.IntFlag{
							Name:  "query, q",
							Value: 0,
							Usage: "Query interval in seconds",
						},
					},
					Action: cliWrapper(updateEnvironment),
				},
				{
					Name:  "add-scheduled-query",
					Usage: "Add a new query to the osquery schedule for an environment",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Value: "",
							Usage: "Environment to be updated",
						},
						cli.StringFlag{
							Name:  "query, q",
							Value: "",
							Usage: "Query to be added to the schedule",
						},
						cli.StringFlag{
							Name:  "query-name, Q",
							Value: "",
							Usage: "Query name to be idenfified in the schedule",
						},
						cli.IntFlag{
							Name:  "interval, i",
							Value: 0,
							Usage: "Query interval in seconds",
						},
						cli.StringFlag{
							Name:  "platform, p",
							Value: "",
							Usage: "Query to be added to the schedule",
						},
						cli.StringFlag{
							Name:  "version, v",
							Value: "",
							Usage: "Query to be added to the schedule",
						},
					},
					Action: cliWrapper(addScheduledQuery),
				},
				{
					Name:  "add-osquery-option",
					Usage: "Add a new option for the osquery configuration",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Value: "",
							Usage: "Environment to be updated",
						},
						cli.StringFlag{
							Name:  "option, o",
							Value: "",
							Usage: "Option name to be added",
						},
						cli.StringFlag{
							Name:  "type, t",
							Value: "",
							Usage: "Option type for the value (string, int, bool)",
						},
						cli.StringFlag{
							Name:  "string-value, s",
							Usage: "String value for the option",
						},
						cli.IntFlag{
							Name:  "int-value, i",
							Usage: "Integer value for the option",
						},
						cli.BoolFlag{
							Name:  "bool-value, b",
							Usage: "Boolean value for the option",
						},
					},
					Action: cliWrapper(addOsqueryOption),
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Delete an existing TLS environment",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Environment to be deleted",
						},
					},
					Action: cliWrapper(deleteEnvironment),
				},
				{
					Name:    "show",
					Aliases: []string{"s"},
					Usage:   "Show a TLS environment",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Environment to be displayed",
						},
					},
					Action: cliWrapper(showEnvironment),
				},
				{
					Name:    "show-flags",
					Aliases: []string{"w"},
					Usage:   "Show the flags for a TLS environment",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Environment to be displayed",
						},
					},
					Action: cliWrapper(showFlagsEnvironment),
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List all existing TLS environments",
					Action:  cliWrapper(listEnvironment),
				},
				{
					Name:    "quick-add",
					Aliases: []string{"q"},
					Usage:   "Generates one-liner for quick adding nodes to environment",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Environment to be used",
						},
						cli.StringFlag{
							Name:  "target, t",
							Value: "sh",
							Usage: "Type of one-liner",
						},
					},
					Action: cliWrapper(quickAddEnvironment),
				},
				{
					Name:    "flags",
					Aliases: []string{"f"},
					Usage:   "Generates the flags to run nodes in an environment",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Environment to be used",
						},
						cli.StringFlag{
							Name:  "certificate, crt",
							Usage: "Certificate path to be used",
						},
						cli.StringFlag{
							Name:  "secret, s",
							Usage: "Secret file path to be used",
						},
					},
					Action: cliWrapper(flagsEnvironment),
				},
				{
					Name:    "secret",
					Aliases: []string{"x"},
					Usage:   "Output the secret to enroll nodes in an environment",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Environment to be used",
						},
					},
					Action: cliWrapper(secretEnvironment),
				},
			},
		},
		{
			Name:  "settings",
			Usage: "Commands for settings",
			Subcommands: []cli.Command{
				{
					Name:    "add",
					Aliases: []string{"a"},
					Usage:   "Add a new settings value",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Value name to be added",
						},
						cli.StringFlag{
							Name:  "service, s",
							Usage: "Value service to be added",
						},
						cli.StringFlag{
							Name:  "type, t",
							Usage: "Value type to be added",
						},
						cli.StringFlag{
							Name:  "string",
							Value: "",
							Usage: "Value string",
						},
						cli.Int64Flag{
							Name:  "integer",
							Value: 0,
							Usage: "Value integer",
						},
						cli.BoolFlag{
							Name:   "boolean",
							Hidden: false,
							Usage:  "Value boolean",
						},
						cli.StringFlag{
							Name:  "info, i",
							Value: "",
							Usage: "Setting info",
						},
					},
					Action: cliWrapper(addSetting),
				},
				{
					Name:    "update",
					Aliases: []string{"u"},
					Usage:   "Update a configuration value",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Value name to be updated",
						},
						cli.StringFlag{
							Name:  "service, s",
							Usage: "Value service to be updated",
						},
						cli.StringFlag{
							Name:  "type, t",
							Usage: "Value type to be updated",
						},
						cli.StringFlag{
							Name:  "string",
							Value: "",
							Usage: "Value string",
						},
						cli.Int64Flag{
							Name:  "integer",
							Value: 0,
							Usage: "Value integer",
						},
						cli.BoolFlag{
							Name:   "true",
							Hidden: false,
							Usage:  "Value boolean true",
						},
						cli.BoolFlag{
							Name:   "false",
							Hidden: false,
							Usage:  "Value boolean false",
						},
						cli.StringFlag{
							Name:  "info, i",
							Value: "",
							Usage: "Setting info",
						},
					},
					Action: cliWrapper(updateSetting),
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Delete an existing configuration value",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Value name to be deleted",
						},
						cli.StringFlag{
							Name:  "service, s",
							Usage: "Value service to be deleted",
						},
					},
					Action: cliWrapper(deleteSetting),
				},
				{
					Name:    "show",
					Aliases: []string{"s"},
					Usage:   "Show all configuration values",
					Action:  cliWrapper(listConfiguration),
				},
			},
		},
		{
			Name:  "node",
			Usage: "Commands for nodes",
			Subcommands: []cli.Command{
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Delete and archive an existing node",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "uuid, u",
							Usage: "Node UUID to be deleted",
						},
					},
					Action: cliWrapper(deleteNode),
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List enrolled nodes",
					Flags: []cli.Flag{
						cli.BoolFlag{
							Name:   "all, v",
							Hidden: false,
							Usage:  "Show all nodes",
						},
						cli.BoolFlag{
							Name:   "active, a",
							Hidden: true,
							Usage:  "Show active nodes",
						},
						cli.BoolFlag{
							Name:   "inactive, i",
							Hidden: false,
							Usage:  "Show inactive nodes",
						},
					},
					Action: cliWrapper(listNodes),
				},
			},
		},
		{
			Name:  "query",
			Usage: "Commands for queries",
			Subcommands: []cli.Command{
				{
					Name:    "complete",
					Aliases: []string{"c"},
					Usage:   "Mark an on-demand query as completed",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Query name to be completed",
						},
					},
					Action: cliWrapper(completeQuery),
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Mark an on-demand query as deleted",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Query name to be deleted",
						},
					},
					Action: cliWrapper(deleteQuery),
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List on-demand queries",
					Flags: []cli.Flag{
						cli.BoolFlag{
							Name:   "all, v",
							Hidden: true,
							Usage:  "Show all queries",
						},
						cli.BoolFlag{
							Name:   "active, a",
							Hidden: false,
							Usage:  "Show active queries",
						},
						cli.BoolFlag{
							Name:   "completed, c",
							Hidden: false,
							Usage:  "Show completed queries",
						},
						cli.BoolFlag{
							Name:   "deleted, d",
							Hidden: false,
							Usage:  "Show deleted queries",
						},
					},
					Action: cliWrapper(listQueries),
				},
			},
		},
		{
			Name:  "tag",
			Usage: "Commands for tags",
			Subcommands: []cli.Command{
				{
					Name:    "add",
					Aliases: []string{"a"},
					Usage:   "Add a new tag",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Tage name to be added",
						},
						cli.StringFlag{
							Name:  "color, c",
							Value: "",
							Usage: "Tag color to be added",
						},
						cli.StringFlag{
							Name:  "description, d",
							Usage: "Tag description to be added",
						},
						cli.StringFlag{
							Name:  "icon, i",
							Value: "",
							Usage: "Tag icon to be added",
						},
					},
					Action: cliWrapper(addTag),
				},
				{
					Name:    "edit",
					Aliases: []string{"e"},
					Usage:   "Edit values for an existing tag",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Tage name to be edited",
						},
						cli.StringFlag{
							Name:  "color, c",
							Usage: "Tag color to be edited",
						},
						cli.StringFlag{
							Name:  "description, d",
							Usage: "Tag description to be edited",
						},
						cli.StringFlag{
							Name:  "icon, i",
							Usage: "Tag icon to be edited",
						},
					},
					Action: cliWrapper(editTag),
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Delete an existing tag",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Tag name to be deleted",
						},
					},
					Action: cliWrapper(deleteTag),
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List all tags",
					Action:  cliWrapper(listTags),
				},
				{
					Name:    "show",
					Aliases: []string{"s"},
					Usage:   "Show an existing tag",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Tag name to be displayed",
						},
					},
					Action: cliWrapper(showTag),
				},
			},
		},
		{
			Name:   "check",
			Usage:  "Checks DB connection",
			Action: checkDB,
		},
	}
}

// Action for the DB check
func checkDB(c *cli.Context) error {
	if err := dbConnection(dbConfigFile); err != nil {
		return fmt.Errorf("Error connecting to DB - %v", err)
	}
	// Should be good
	return nil
}

// Function to load and connect to DB
func dbConnection(config string) error {
	// Database handler
	dbConfig, err := backend.LoadConfiguration(dbConfigFile, backend.DBKey)
	if err != nil {
		log.Fatalf("Failed to load DB configuration - %v", err)
	}
	db, err = backend.GetDB(dbConfig)
	if err != nil {
		log.Fatalf("Failed to load DB - %v", err)
	}
	// Check if connection is ready
	if err := db.DB().Ping(); err != nil {
		return fmt.Errorf("Error pinging DB - %v", err)
	}
	// We are ready
	return nil
}

// Function to wrap actions
func cliWrapper(action func(*cli.Context) error) func(*cli.Context) error {
	return func(c *cli.Context) error {
		// Load and connecto to DB
		if err := dbConnection(dbConfigFile); err != nil {
			return err
		}
		// Initialize users
		adminUsers = users.CreateUserManager(db, nil)
		// Initialize environment
		envs = environments.CreateEnvironment(db)
		// Initialize settings
		settingsmgr = settings.NewSettings(db)
		// Initialize nodes
		nodesmgr = nodes.CreateNodes(db)
		// Initialize queries
		queriesmgr = queries.CreateQueries(db)
		// Initialize tags
		tagsmgr = tags.CreateTagManager(db)
		// Execute action
		return action(c)
	}
}

// Action to run when no flags are provided
func cliAction(c *cli.Context) error {
	if c.NumFlags() == 0 {
		if err := cli.ShowAppHelp(c); err != nil {
			log.Fatalf("Error with CLI help - %s", err)
		}
		return cli.NewExitError("\nNo flags provided", 2)
	}
	return nil
}

// Go go!
func main() {
	// Let's go!
	app = cli.NewApp()
	app.Name = appName
	app.Usage = appUsage
	app.Version = appVersion
	app.Description = appDescription
	app.Flags = flags
	app.Commands = commands
	app.Action = cliAction
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("Failed to execute %v", err)
	}
}
