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
	"github.com/jmpsec/osctrl/types"
	"github.com/jmpsec/osctrl/users"
	"github.com/jmpsec/osctrl/version"

	"github.com/urfave/cli/v2"
)

const (
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
	err         error
	app         *cli.App
	dbConfig    backend.JSONConfigurationDB
	apiConfig   JSONConfigurationAPI
	flags       []cli.Flag
	commands    []*cli.Command
	settingsmgr *settings.Settings
	nodesmgr    *nodes.NodeManager
	queriesmgr  *queries.Queries
	adminUsers  *users.UserManager
	tagsmgr     *tags.TagManager
	envs        *environments.Environment
	db          *backend.DBManager
	osctrlAPI   *OsctrlAPI
)

// Variables for flags
var (
	dbFlag        bool
	apiFlag       bool
	jsonFlag      bool
	csvFlag       bool
	prettyFlag    bool
	insecureFlag  bool
	dbConfigFile  string
	apiConfigFile string
)

// Initialization code
func init() {
	// Initialize CLI flags
	flags = []cli.Flag{
		&cli.BoolFlag{
			Name:        "db",
			Aliases:     []string{"d"},
			Value:       false,
			Usage:       "Connect to local osctrl DB using JSON config file",
			EnvVars:     []string{"DB_CONFIG"},
			Destination: &dbFlag,
		},
		&cli.BoolFlag{
			Name:        "api",
			Aliases:     []string{"a"},
			Value:       true,
			Usage:       "Connect to remote osctrl using JSON config file",
			EnvVars:     []string{"API_CONFIG"},
			Destination: &apiFlag,
		},
		&cli.StringFlag{
			Name:        "api-file",
			Aliases:     []string{"A"},
			Value:       "",
			Usage:       "Load API JSON configuration from `FILE`",
			EnvVars:     []string{"API_CONFIG_FILE"},
			Destination: &apiConfigFile,
		},
		&cli.StringFlag{
			Name:        "api-url",
			Aliases:     []string{"U"},
			Usage:       "The URL for osctrl API to be used",
			EnvVars:     []string{"API_URL"},
			Destination: &apiConfig.URL,
		},
		&cli.StringFlag{
			Name:        "api-token",
			Aliases:     []string{"T"},
			Usage:       "Token to authenticate with the osctrl API",
			EnvVars:     []string{"API_TOKEN"},
			Destination: &apiConfig.Token,
		},
		&cli.StringFlag{
			Name:        "db-file",
			Aliases:     []string{"D"},
			Value:       "",
			Usage:       "Load DB JSON configuration from `FILE`",
			EnvVars:     []string{"DB_CONFIG_FILE"},
			Destination: &dbConfigFile,
		},
		&cli.StringFlag{
			Name:        "db-host",
			Value:       "127.0.0.1",
			Usage:       "Backend host to be connected to",
			EnvVars:     []string{"DB_HOST"},
			Destination: &dbConfig.Host,
		},
		&cli.StringFlag{
			Name:        "db-port",
			Value:       "5432",
			Usage:       "Backend port to be connected to",
			EnvVars:     []string{"DB_PORT"},
			Destination: &dbConfig.Port,
		},
		&cli.StringFlag{
			Name:        "db-name",
			Value:       "osctrl",
			Usage:       "Database name to be used in the backend",
			EnvVars:     []string{"DB_NAME"},
			Destination: &dbConfig.Name,
		},
		&cli.StringFlag{
			Name:        "db-user",
			Value:       "postgres",
			Usage:       "Username to be used for the backend",
			EnvVars:     []string{"DB_USER"},
			Destination: &dbConfig.Username,
		},
		&cli.StringFlag{
			Name:        "db-pass",
			Value:       "postgres",
			Usage:       "Password to be used for the backend",
			EnvVars:     []string{"DB_PASS"},
			Destination: &dbConfig.Password,
		},
		&cli.IntFlag{
			Name:        "db-max-idle-conns",
			Value:       20,
			Usage:       "Maximum number of connections in the idle connection pool",
			EnvVars:     []string{"DB_MAX_IDLE_CONNS"},
			Destination: &dbConfig.MaxIdleConns,
		},
		&cli.IntFlag{
			Name:        "db-max-open-conns",
			Value:       100,
			Usage:       "Maximum number of open connections to the database",
			EnvVars:     []string{"DB_MAX_OPEN_CONNS"},
			Destination: &dbConfig.MaxOpenConns,
		},
		&cli.IntFlag{
			Name:        "db-conn-max-lifetime",
			Value:       30,
			Usage:       "Maximum amount of time a connection may be reused",
			EnvVars:     []string{"DB_CONN_MAX_LIFETIME"},
			Destination: &dbConfig.ConnMaxLifetime,
		},
		&cli.BoolFlag{
			Name:        "insecure",
			Aliases:     []string{"i"},
			Value:       false,
			Usage:       "Allow insecure server connections when using SSL",
			Destination: &insecureFlag,
		},
		&cli.BoolFlag{
			Name:        "json",
			Aliases:     []string{"j"},
			Value:       false,
			Usage:       "Print output in JSON format",
			Destination: &jsonFlag,
		},
		&cli.BoolFlag{
			Name:        "csv",
			Aliases:     []string{"c"},
			Value:       false,
			Usage:       "Print output in CSV format",
			Destination: &csvFlag,
		},
		&cli.BoolFlag{
			Name:        "pretty",
			Aliases:     []string{"p"},
			Value:       true,
			Usage:       "Print output in pretty format (table)",
			Destination: &prettyFlag,
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
							Aliases: []string{"e"},
							Value:   "",
							Usage:   "Default environment for the new user",
						},
						&cli.StringFlag{
							Name:    "email",
							Aliases: []string{"E"},
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
							Aliases: []string{"E"},
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
							Aliases: []string{"env"},
							Usage:   "Default environment for this user",
						},
					},
					Action: cliWrapper(editUser),
				},
				{
					Name:    "permissions",
					Aliases: []string{"p"},
					Usage:   "Permission actions for an existing user",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "username",
							Aliases: []string{"u"},
							Usage:   "User to perform the action",
						},
						&cli.StringFlag{
							Name:    "environment",
							Aliases: []string{"e"},
							Usage:   "Environment for this user",
						},
						&cli.BoolFlag{
							Name:    "admin",
							Aliases: []string{"a"},
							Hidden:  false,
							Usage:   "Grant admin permissions",
						},
						&cli.BoolFlag{
							Name:    "user",
							Aliases: []string{"U"},
							Hidden:  false,
							Usage:   "Grant user permissions",
						},
						&cli.BoolFlag{
							Name:    "query",
							Aliases: []string{"q"},
							Hidden:  false,
							Usage:   "Grant query permissions",
						},
						&cli.BoolFlag{
							Name:    "carve",
							Aliases: []string{"c"},
							Hidden:  false,
							Usage:   "Grant carve permissions",
						},
						&cli.BoolFlag{
							Name:    "reset",
							Aliases: []string{"R"},
							Hidden:  false,
							Usage:   "Reset permissions for this user",
						},
						&cli.BoolFlag{
							Name:    "show",
							Aliases: []string{"s"},
							Hidden:  false,
							Usage:   "Display all permissions for this user",
						},
					},
					Action: cliWrapper(permissionsUser),
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
					Name:    "show",
					Aliases: []string{"s"},
					Usage:   "Show an existing user",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "username",
							Aliases: []string{"u"},
							Usage:   "User to be displayed",
						},
					},
					Action: cliWrapper(showUser),
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
							Usage:   "Environment name to be added",
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
							Value:   "",
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
							Usage:   "Environment name to be updated",
						},
						&cli.BoolFlag{
							Name:    "debug",
							Aliases: []string{"d"},
							Usage:   "Environment debug capability",
						},
						&cli.BoolFlag{
							Name:    "enroll",
							Aliases: []string{"e"},
							Usage:   "Environment enroll capability",
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
							Usage:   "Environment name to be updated",
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
							Usage:   "Environment name to be updated",
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
							Usage:   "Environment name to be updated",
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
							Usage:   "Environment name to be updated",
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
							Usage:   "Environment name to be updated",
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
							Usage:   "Environment name to be updated",
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
							Usage:   "Environment name to be updated",
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
							Usage:   "Environment name to be updated",
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
							Usage:   "Environment name to be updated",
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
							Usage:   "Environment name to be deleted",
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
							Usage:   "Environment name to be displayed",
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
							Usage:   "Environment name to be displayed",
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
							Usage:   "Environment name to be used",
						},
						&cli.StringFlag{
							Name:    "target",
							Aliases: []string{"t"},
							Value:   "sh",
							Usage:   "Type of one-liner",
						},
						&cli.BoolFlag{
							Name:    "insecure",
							Aliases: []string{"i"},
							Value:   false,
							Usage:   "Generate insecure one-liner",
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
							Usage:   "Environment name to be used",
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
							Usage:   "Environment name to be used",
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
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
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
							Name:    "active",
							Aliases: []string{"a"},
							Hidden:  false,
							Value:   true,
							Usage:   "Show active nodes",
						},
						&cli.BoolFlag{
							Name:    "all, A",
							Aliases: []string{"A"},
							Hidden:  false,
							Usage:   "Show all nodes",
						},
						&cli.BoolFlag{
							Name:    "inactive, i",
							Aliases: []string{"i"},
							Hidden:  false,
							Usage:   "Show inactive nodes",
						},
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
						},
					},
					Action: cliWrapper(listNodes),
				},
				{
					Name:    "show",
					Aliases: []string{"s"},
					Usage:   "Show an existing node",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "uuid",
							Aliases: []string{"u"},
							Usage:   "Node UUID to be shown",
						},
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
						},
					},
					Action: cliWrapper(showNode),
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
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
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
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
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
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
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
			Name:   "check-db",
			Usage:  "Checks DB connection",
			Action: checkDB,
		},
		{
			Name:   "check-api",
			Usage:  "Checks API token",
			Action: checkAPI,
		},
	}
}

// Action for the DB check
func checkDB(c *cli.Context) error {
	if dbFlag {
		// Initialize backend
		db, err = backend.CreateDBManagerFile(dbConfigFile)
		if err != nil {
			return fmt.Errorf("Failed to create backend - %v", err)
		}
	} else {
		db, err = backend.CreateDBManager(dbConfig)
		if err != nil {
			return fmt.Errorf("Failed to create backend - %v", err)
		}
	}
	if err := db.Check(); err != nil {
		return err
	}
	// Should be good
	return nil
}

// Action for the API check
func checkAPI(c *cli.Context) error {
	if apiFlag {
		if apiConfigFile != "" {
			apiConfig, err = loadAPIConfiguration(apiConfigFile)
			if err != nil {
				return fmt.Errorf("loadAPIConfiguration - %v", err)
			}
		}
		// Initialize API
		osctrlAPI = CreateAPI(apiConfig, insecureFlag)
	}
	// Should be good
	return nil
}

// Function to wrap actions
func cliWrapper(action func(*cli.Context) error) func(*cli.Context) error {
	return func(c *cli.Context) error {
		// DB connection will be used
		if dbFlag {
			// Initialize backend
			if dbConfigFile != "" {
				db, err = backend.CreateDBManagerFile(dbConfigFile)
				if err != nil {
					return fmt.Errorf("CreateDBManagerFile - %v", err)
				}
			} else {
				db, err = backend.CreateDBManager(dbConfig)
				if err != nil {
					return fmt.Errorf("CreateDBManager - %v", err)
				}
			}
			// Initialize users
			adminUsers = users.CreateUserManager(db.Conn, &types.JSONConfigurationJWT{JWTSecret: appName})
			// Initialize environment
			envs = environments.CreateEnvironment(db.Conn)
			// Initialize settings
			settingsmgr = settings.NewSettings(db.Conn)
			// Initialize nodes
			nodesmgr = nodes.CreateNodes(db.Conn)
			// Initialize queries
			queriesmgr = queries.CreateQueries(db.Conn)
			// Initialize tags
			tagsmgr = tags.CreateTagManager(db.Conn)
			// Execute action
			return action(c)
		}
		if apiFlag {
			if apiConfigFile != "" {
				apiConfig, err = loadAPIConfiguration(apiConfigFile)
				if err != nil {
					return fmt.Errorf("loadAPIConfiguration - %v", err)
				}
			}
			// Initialize API
			osctrlAPI = CreateAPI(apiConfig, insecureFlag)
			// Execute action
			return action(c)
		}
		// If we are here, nor DB or API has been enabled
		return nil
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
