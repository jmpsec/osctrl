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
	"github.com/jmpsec/osctrl/version"

	"github.com/jinzhu/gorm"
	"github.com/urfave/cli/v2"
)

const (
	// DB configuration file
	defDBConfigurationFile string = "config/db.json"
	// Project name
	projectName string = "osctrl"
	// Application name
	appName string = projectName + "-cli"
	// Application version
	appVersion string = version.OsctrlVersion
	// Application usage
	appUsage string = "CLI for " + projectName
	// Application description
	appDescription string = appUsage + ", a fast and efficient osquery management"
)

// Global variables
var (
	db          *gorm.DB
	app         *cli.App
	flags       []cli.Flag
	commands    []*cli.Command
	settingsmgr *settings.Settings
	nodesmgr    *nodes.NodeManager
	queriesmgr  *queries.Queries
	adminUsers  *users.UserManager
	tagsmgr     *tags.TagManager
	envs        *environments.Environment
)

// Variables for flags
var (
	configFile   string
	dbFlag       bool
	dbConfigFile string
)

// Initialization code
func init() {
	// Initialize CLI flags
	flags = []cli.Flag{
		&cli.BoolFlag{
			Name:        "db",
			Aliases:     []string{"d"},
			Value:       false,
			Usage:       "Provide DB configuration via JSON file",
			EnvVars:     []string{"DB_CONFIG"},
			Destination: &dbFlag,
		},
		&cli.StringFlag{
			Name:        "db-file",
			Aliases:     []string{"D"},
			Value:       defDBConfigurationFile,
			Usage:       "Load DB configuration from `FILE`",
			EnvVars:     []string{"DB_CONFIG_FILE"},
			Destination: &configFile,
		},
	}
	// Initialize CLI flags commands
	commands = []*cli.Command{
		{
			Name:  "user",
			Usage: "Commands for users",
			Subcommands: []*cli.Command{
				{
					Name:    "add",
					Aliases: []string{"a"},
					Usage:   "Add a new user",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "username",
							Aliases: []string{"u"},
							Usage:   "Username for the new user",
						},
						&cli.StringFlag{
							Name:    "password",
							Aliases: []string{"p"},
							Usage:   "Password for the new user",
						},
						&cli.BoolFlag{
							Name:    "admin",
							Aliases: []string{"a"},
							Hidden:  false,
							Usage:   "Make this user an admin",
						},
						&cli.StringFlag{
							Name:    "environment",
							Aliases: []string{"E"},
							Value:   "",
							Usage:   "Default environment for the new user",
						},
						&cli.StringFlag{
							Name:    "email",
							Aliases: []string{"e"},
							Usage:   "Email for the new user",
						},
						&cli.StringFlag{
							Name:    "fullname",
							Aliases: []string{"n"},
							Usage:   "Full name for the new user",
						},
					},
					Action: cliWrapper(addUser),
				},
				{
					Name:    "edit",
					Aliases: []string{"e"},
					Usage:   "Edit an existing user",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "username",
							Aliases: []string{"u"},
							Usage:   "User to be edited",
						},
						&cli.StringFlag{
							Name:    "password",
							Aliases: []string{"p"},
							Usage:   "New password to be used",
						},
						&cli.StringFlag{
							Name:    "email",
							Aliases: []string{"e"},
							Usage:   "Email to be used",
						},
						&cli.StringFlag{
							Name:    "fullname",
							Aliases: []string{"n"},
							Usage:   "Full name to be used",
						},
						&cli.BoolFlag{
							Name:    "admin",
							Aliases: []string{"a"},
							Hidden:  false,
							Usage:   "Make this user an admin",
						},
						&cli.BoolFlag{
							Name:    "non-admin",
							Aliases: []string{"d"},
							Hidden:  false,
							Usage:   "Make this user an non-admin",
						},
						&cli.StringFlag{
							Name:    "environment",
							Aliases: []string{"E"},
							Usage:   "Default environment for this user",
						},
					},
					Action: cliWrapper(editUser),
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Delete an existing user",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "username",
							Aliases: []string{"u"},
							Usage:   "User to be deleted",
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
			Subcommands: []*cli.Command{
				{
					Name:    "add",
					Aliases: []string{"a"},
					Usage:   "Add a new TLS environment",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Environment to be added",
						},
						&cli.StringFlag{
							Name:    "hostname",
							Aliases: []string{"host"},
							Usage:   "Environment host to be added",
						},
						&cli.BoolFlag{
							Name:    "debug",
							Aliases: []string{"d"},
							Hidden:  false,
							Usage:   "Environment debug capability",
						},
						&cli.StringFlag{
							Name:    "certificate",
							Aliases: []string{"crt"},
							Usage:   "Certificate file to be read",
						},
					},
					Action: cliWrapper(addEnvironment),
				},
				{
					Name:    "update",
					Aliases: []string{"u"},
					Usage:   "Update an existing TLS environment",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Environment to be updated",
						},
						&cli.BoolFlag{
							Name:    "debug",
							Aliases: []string{"d"},
							Usage:   "Environment debug capability",
						},
						&cli.StringFlag{
							Name:    "hostname",
							Aliases: []string{"host"},
							Usage:   "Environment host to be updated",
						},
						&cli.IntFlag{
							Name:    "logging",
							Aliases: []string{"l"},
							Value:   0,
							Usage:   "Logging interval in seconds",
						},
						&cli.IntFlag{
							Name:    "config",
							Aliases: []string{"c"},
							Value:   0,
							Usage:   "Config interval in seconds",
						},
						&cli.IntFlag{
							Name:    "query",
							Aliases: []string{"q"},
							Value:   0,
							Usage:   "Query interval in seconds",
						},
					},
					Action: cliWrapper(updateEnvironment),
				},
				{
					Name:  "add-scheduled-query",
					Usage: "Add a new query to the osquery schedule for an environment",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Value:   "",
							Usage:   "Environment to be updated",
						},
						&cli.StringFlag{
							Name:    "query",
							Aliases: []string{"q"},
							Value:   "",
							Usage:   "Query to be added to the schedule",
						},
						&cli.StringFlag{
							Name:    "query-name",
							Aliases: []string{"Q"},
							Value:   "",
							Usage:   "Query name to be idenfified in the schedule",
						},
						&cli.IntFlag{
							Name:    "interval",
							Aliases: []string{"i"},
							Value:   0,
							Usage:   "Query interval in seconds",
						},
						&cli.StringFlag{
							Name:    "platform",
							Aliases: []string{"p"},
							Value:   "",
							Usage:   "Restrict this query to a given platform",
						},
						&cli.StringFlag{
							Name:    "version",
							Aliases: []string{"v"},
							Value:   "",
							Usage:   "Only run on osquery versions greater than or equal-to this version",
						},
					},
					Action: cliWrapper(addScheduledQuery),
				},
				{
					Name:  "remove-scheduled-query",
					Usage: "Remove query from the osquery schedule for an environment",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Value:   "",
							Usage:   "Environment to be updated",
						},
						&cli.StringFlag{
							Name:    "query-name",
							Aliases: []string{"q"},
							Value:   "",
							Usage:   "Query to be removed from the schedule",
						},
					},
					Action: cliWrapper(removeScheduledQuery),
				},
				{
					Name:  "add-osquery-option",
					Usage: "Add or change an osquery option to the configuration",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Value:   "",
							Usage:   "Environment to be updated",
						},
						&cli.StringFlag{
							Name:    "option",
							Aliases: []string{"o"},
							Value:   "",
							Usage:   "Option name to be added",
						},
						&cli.StringFlag{
							Name:    "type",
							Aliases: []string{"t"},
							Value:   "",
							Usage:   "Option type for the value (string, int, bool)",
						},
						&cli.StringFlag{
							Name:    "string-value",
							Aliases: []string{"s"},
							Usage:   "String value for the option",
						},
						&cli.IntFlag{
							Name:    "int-value",
							Aliases: []string{"i"},
							Usage:   "Integer value for the option",
						},
						&cli.BoolFlag{
							Name:    "bool-value",
							Aliases: []string{"b"},
							Usage:   "Boolean value for the option",
						},
					},
					Action: cliWrapper(addOsqueryOption),
				},
				{
					Name:  "remove-osquery-option",
					Usage: "Remove an option for the osquery configuration",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Value:   "",
							Usage:   "Environment to be updated",
						},
						&cli.StringFlag{
							Name:    "option",
							Aliases: []string{"o"},
							Value:   "",
							Usage:   "Option name to be added",
						},
					},
					Action: cliWrapper(removeOsqueryOption),
				},
				{
					Name:  "add-new-pack",
					Usage: "Add a new query pack to the osquery configuration",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Value:   "",
							Usage:   "Environment to be updated",
						},
						&cli.StringFlag{
							Name:    "pack",
							Aliases: []string{"p"},
							Value:   "",
							Usage:   "Pack name to be added",
						},
						&cli.StringFlag{
							Name:    "platform",
							Aliases: []string{"P"},
							Usage:   "Restrict this pack to a given platform",
						},
						&cli.StringFlag{
							Name:    "version",
							Aliases: []string{"v"},
							Usage:   "Only run on osquery versions greater than or equal-to this version",
						},
						&cli.IntFlag{
							Name:    "shard",
							Aliases: []string{"s"},
							Usage:   "Restrict this query to a percentage (1-100) of target hosts",
						},
					},
					Action: cliWrapper(addNewPack),
				},
				{
					Name:  "add-local-pack",
					Usage: "Add a new local query pack to the osquery configuration",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Value:   "",
							Usage:   "Environment to be updated",
						},
						&cli.StringFlag{
							Name:    "pack",
							Aliases: []string{"p"},
							Value:   "",
							Usage:   "Pack name to be added",
						},
						&cli.StringFlag{
							Name:    "pack-path",
							Aliases: []string{"P"},
							Usage:   "Local full path to load the query pack within osquery",
						},
					},
					Action: cliWrapper(addLocalPack),
				},
				{
					Name:  "remove-pack",
					Usage: "Remove query pack from the osquery configuration",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Value:   "",
							Usage:   "Environment to be updated",
						},
						&cli.StringFlag{
							Name:    "pack",
							Aliases: []string{"p"},
							Value:   "",
							Usage:   "Pack name to be removed",
						},
					},
					Action: cliWrapper(removePack),
				},
				{
					Name:  "add-query-to-pack",
					Usage: "Add a new query to the given query pack",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Value:   "",
							Usage:   "Environment to be updated",
						},
						&cli.StringFlag{
							Name:    "pack",
							Aliases: []string{"p"},
							Value:   "",
							Usage:   "Environment to be updated",
						},
						&cli.StringFlag{
							Name:    "query",
							Aliases: []string{"q"},
							Value:   "",
							Usage:   "Query to be added to the pack",
						},
						&cli.StringFlag{
							Name:    "query-name",
							Aliases: []string{"Q"},
							Value:   "",
							Usage:   "Query name to be added to the pack",
						},
						&cli.IntFlag{
							Name:    "interval",
							Aliases: []string{"i"},
							Value:   0,
							Usage:   "Query interval in seconds",
						},
						&cli.StringFlag{
							Name:    "platform",
							Aliases: []string{"P"},
							Value:   "",
							Usage:   "Restrict this query to a given platform",
						},
						&cli.StringFlag{
							Name:    "version",
							Aliases: []string{"v"},
							Value:   "",
							Usage:   "Only run on osquery versions greater than or equal-to this version",
						},
					},
					Action: cliWrapper(addPackQuery),
				},
				{
					Name:  "remove-query-from-pack",
					Usage: "Remove query from the given query pack",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Value:   "",
							Usage:   "Environment to be updated",
						},
						&cli.StringFlag{
							Name:    "pack",
							Aliases: []string{"p"},
							Value:   "",
							Usage:   "Pack name to be updated",
						},
						&cli.StringFlag{
							Name:    "query-name",
							Aliases: []string{"q"},
							Value:   "",
							Usage:   "Query name to be removed",
						},
					},
					Action: cliWrapper(removePackQuery),
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Delete an existing TLS environment",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Environment to be deleted",
						},
					},
					Action: cliWrapper(deleteEnvironment),
				},
				{
					Name:    "show",
					Aliases: []string{"s"},
					Usage:   "Show a TLS environment",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Environment to be displayed",
						},
					},
					Action: cliWrapper(showEnvironment),
				},
				{
					Name:    "show-flags",
					Aliases: []string{"w"},
					Usage:   "Show the flags for a TLS environment",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Environment to be displayed",
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
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Environment to be used",
						},
						&cli.StringFlag{
							Name:    "target",
							Aliases: []string{"t"},
							Value:   "sh",
							Usage:   "Type of one-liner",
						},
					},
					Action: cliWrapper(quickAddEnvironment),
				},
				{
					Name:    "flags",
					Aliases: []string{"f"},
					Usage:   "Generates the flags to run nodes in an environment",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Environment to be used",
						},
						&cli.StringFlag{
							Name:    "certificate",
							Aliases: []string{"crt"},
							Usage:   "Certificate path to be used",
						},
						&cli.StringFlag{
							Name:    "secret",
							Aliases: []string{"s"},
							Usage:   "Secret file path to be used",
						},
					},
					Action: cliWrapper(flagsEnvironment),
				},
				{
					Name:    "secret",
					Aliases: []string{"x"},
					Usage:   "Output the secret to enroll nodes in an environment",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Environment to be used",
						},
					},
					Action: cliWrapper(secretEnvironment),
				},
			},
		},
		{
			Name:  "settings",
			Usage: "Commands for settings",
			Subcommands: []*cli.Command{
				{
					Name:    "add",
					Aliases: []string{"a"},
					Usage:   "Add a new settings value",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Value name to be added",
						},
						&cli.StringFlag{
							Name:    "service",
							Aliases: []string{"s"},
							Usage:   "Value service to be added",
						},
						&cli.StringFlag{
							Name:    "type, t",
							Aliases: []string{"t"},
							Usage:   "Value type to be added",
						},
						&cli.StringFlag{
							Name:  "string",
							Value: "",
							Usage: "Value string",
						},
						&cli.Int64Flag{
							Name:  "integer",
							Value: 0,
							Usage: "Value integer",
						},
						&cli.BoolFlag{
							Name:   "boolean",
							Hidden: false,
							Usage:  "Value boolean",
						},
						&cli.StringFlag{
							Name:    "info",
							Aliases: []string{"i"},
							Value:   "",
							Usage:   "Setting info",
						},
					},
					Action: cliWrapper(addSetting),
				},
				{
					Name:    "update",
					Aliases: []string{"u"},
					Usage:   "Update a configuration value",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Value name to be updated",
						},
						&cli.StringFlag{
							Name:    "service",
							Aliases: []string{"s"},
							Usage:   "Value service to be updated",
						},
						&cli.StringFlag{
							Name:    "type",
							Aliases: []string{"t"},
							Usage:   "Value type to be updated",
						},
						&cli.StringFlag{
							Name:  "string",
							Value: "",
							Usage: "Value string",
						},
						&cli.Int64Flag{
							Name:  "integer",
							Value: 0,
							Usage: "Value integer",
						},
						&cli.BoolFlag{
							Name:   "true",
							Hidden: false,
							Usage:  "Value boolean true",
						},
						&cli.BoolFlag{
							Name:   "false",
							Hidden: false,
							Usage:  "Value boolean false",
						},
						&cli.StringFlag{
							Name:    "info",
							Aliases: []string{"i"},
							Value:   "",
							Usage:   "Setting info",
						},
					},
					Action: cliWrapper(updateSetting),
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Delete an existing configuration value",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Value name to be deleted",
						},
						&cli.StringFlag{
							Name:    "service",
							Aliases: []string{"s"},
							Usage:   "Value service to be deleted",
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
			Subcommands: []*cli.Command{
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Delete and archive an existing node",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "uuid, u",
							Aliases: []string{"u"},
							Usage:   "Node UUID to be deleted",
						},
					},
					Action: cliWrapper(deleteNode),
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List enrolled nodes",
					Flags: []cli.Flag{
						&cli.BoolFlag{
							Name:    "all, v",
							Aliases: []string{"v"},
							Hidden:  false,
							Usage:   "Show all nodes",
						},
						&cli.BoolFlag{
							Name:    "active",
							Aliases: []string{"a"},
							Hidden:  true,
							Usage:   "Show active nodes",
						},
						&cli.BoolFlag{
							Name:    "inactive, i",
							Aliases: []string{"i"},
							Hidden:  false,
							Usage:   "Show inactive nodes",
						},
					},
					Action: cliWrapper(listNodes),
				},
			},
		},
		{
			Name:  "query",
			Usage: "Commands for queries",
			Subcommands: []*cli.Command{
				{
					Name:    "complete",
					Aliases: []string{"c"},
					Usage:   "Mark an on-demand query as completed",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Query name to be completed",
						},
					},
					Action: cliWrapper(completeQuery),
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Mark an on-demand query as deleted",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Query name to be deleted",
						},
					},
					Action: cliWrapper(deleteQuery),
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List on-demand queries",
					Flags: []cli.Flag{
						&cli.BoolFlag{
							Name:    "all",
							Aliases: []string{"v"},
							Hidden:  true,
							Usage:   "Show all queries",
						},
						&cli.BoolFlag{
							Name:    "active",
							Aliases: []string{"a"},
							Hidden:  false,
							Usage:   "Show active queries",
						},
						&cli.BoolFlag{
							Name:    "completed, c",
							Aliases: []string{"c"},
							Hidden:  false,
							Usage:   "Show completed queries",
						},
						&cli.BoolFlag{
							Name:    "deleted",
							Aliases: []string{"d"},
							Hidden:  false,
							Usage:   "Show deleted queries",
						},
					},
					Action: cliWrapper(listQueries),
				},
			},
		},
		{
			Name:  "tag",
			Usage: "Commands for tags",
			Subcommands: []*cli.Command{
				{
					Name:    "add",
					Aliases: []string{"a"},
					Usage:   "Add a new tag",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Tage name to be added",
						},
						&cli.StringFlag{
							Name:    "color",
							Aliases: []string{"c"},
							Value:   "",
							Usage:   "Tag color to be added",
						},
						&cli.StringFlag{
							Name:    "description, d",
							Aliases: []string{"d"},
							Usage:   "Tag description to be added",
						},
						&cli.StringFlag{
							Name:    "icon, i",
							Aliases: []string{"i"},
							Value:   "",
							Usage:   "Tag icon to be added",
						},
					},
					Action: cliWrapper(addTag),
				},
				{
					Name:    "edit",
					Aliases: []string{"e"},
					Usage:   "Edit values for an existing tag",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Tage name to be edited",
						},
						&cli.StringFlag{
							Name:    "color",
							Aliases: []string{"c"},
							Usage:   "Tag color to be edited",
						},
						&cli.StringFlag{
							Name:    "description",
							Aliases: []string{"d"},
							Usage:   "Tag description to be edited",
						},
						&cli.StringFlag{
							Name:    "icon",
							Aliases: []string{"i"},
							Usage:   "Tag icon to be edited",
						},
					},
					Action: cliWrapper(editTag),
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Delete an existing tag",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Tag name to be deleted",
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
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Tag name to be displayed",
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
		return cli.Exit("\nNo flags provided", 2)
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
