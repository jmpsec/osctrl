package main

import (
	"fmt"
	"os"

	"github.com/jmpsec/osctrl/pkg/backend"
	"github.com/jmpsec/osctrl/pkg/carves"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/users"
	"github.com/jmpsec/osctrl/pkg/version"
	"github.com/rs/zerolog/log"
	"golang.org/x/term"

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
	// JSON file with API token
	defaultApiConfigFile = projectName + "-api.json"
)

const (
	// Values for output format
	jsonFormat   = "json"
	csvFormat    = "csv"
	prettyFormat = "pretty"
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
	filecarves  *carves.Carves
	adminUsers  *users.UserManager
	tagsmgr     *tags.TagManager
	envs        *environments.Environment
	db          *backend.DBManager
	osctrlAPI   *OsctrlAPI
	formats     map[string]bool
)

// Variables for flags
var (
	dbFlag           bool
	apiFlag          bool
	formatFlag       string
	silentFlag       bool
	insecureFlag     bool
	writeApiFileFlag bool
	dbConfigFile     string
	apiConfigFile    string
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
			Value:       defaultApiConfigFile,
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
		&cli.StringFlag{
			Name:        "output-format",
			Aliases:     []string{"o"},
			Value:       prettyFormat,
			Usage:       "Format to be used for data output",
			EnvVars:     []string{"OUTPUT_FORMAT"},
			Destination: &formatFlag,
		},
		&cli.BoolFlag{
			Name:        "silent",
			Aliases:     []string{"s"},
			Value:       false,
			Usage:       "Silent mode",
			Destination: &silentFlag,
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
					Name:    "change-permissions",
					Aliases: []string{"p", "access"},
					Usage:   "Change permission in an environment for an existing user",
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
					},
					Action: cliWrapper(changePermissions),
				},
				{
					Name:    "reset-permissions",
					Aliases: []string{"R", "reset"},
					Usage:   "Clear and reset permissions for a user in an environment",
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
					},
					Action: cliWrapper(resetPermissions),
				},
				{
					Name:    "show-permissions",
					Aliases: []string{"S", "perms"},
					Usage:   "Show permissions for a user in an environment",
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
					},
					Action: cliWrapper(showPermissions),
				},
				{
					Name:    "all-permissions",
					Aliases: []string{"A", "all-perms"},
					Usage:   "Show all permissions for an existing user",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "username",
							Aliases: []string{"u"},
							Usage:   "User to perform the action",
						},
					},
					Action: cliWrapper(allPermissions),
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
						&cli.StringFlag{
							Name:    "deb",
							Aliases: []string{"deb-package"},
							Usage:   "DEB package to be updated",
						},
						&cli.StringFlag{
							Name:    "rpm",
							Aliases: []string{"rpm-package"},
							Usage:   "RPM package to be updated",
						},
						&cli.StringFlag{
							Name:    "msi",
							Aliases: []string{"msi-package"},
							Usage:   "MSI package to be updated",
						},
						&cli.StringFlag{
							Name:    "pkg",
							Aliases: []string{"pkg-package"},
							Usage:   "PKG package to be updated",
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
					Name: "node-actions",
					Subcommands: []*cli.Command{
						{
							Name:    "show-flags",
							Aliases: []string{"s"},
							Usage:   "Show the enroll flags for a TLS environment",
							Action:  cliWrapper(showFlagsEnvironment),
						},
						{
							Name:    "new-flags",
							Aliases: []string{"f"},
							Usage:   "Generate new enroll flags and save them for a TLS environment",
							Action:  cliWrapper(newFlagsEnvironment),
						},
						{
							Name:    "gen-flags",
							Aliases: []string{"F"},
							Usage:   "Generate and show the enroll flags for a TLS environment",
							Flags: []cli.Flag{
								&cli.StringFlag{
									Name:    "certificate",
									Aliases: []string{"crt"},
									Usage:   "Certificate file path to be used",
								},
								&cli.StringFlag{
									Name:    "secret",
									Aliases: []string{"s"},
									Usage:   "Secret file path to be used",
								},
							},
							Action: cliWrapper(genFlagsEnvironment),
						},
						{
							Name:    "quick-add",
							Aliases: []string{"q"},
							Usage:   "Generates one-liner for quick enrolling nodes to a TLS environment",
							Flags: []cli.Flag{
								&cli.StringFlag{
									Name:    "target",
									Aliases: []string{"t"},
									Value:   "sh",
									Usage:   "Type of one-liner script",
								},
								&cli.BoolFlag{
									Name:    "insecure",
									Aliases: []string{"i"},
									Value:   false,
									Usage:   "Generate insecure one-liner, without HTTPS",
								},
							},
							Action: cliWrapper(quickAddEnvironment),
						},
						{
							Name:    "extend-enroll",
							Aliases: []string{"f"},
							Usage:   "Extend the existing enroll URL for a TLS environment",
							Action:  cliWrapper(extendEnrollEnvironment),
						},
						{
							Name:    "rotate-enroll",
							Aliases: []string{"f"},
							Usage:   "Rotate to a new enroll URL for a TLS environment",
							Action:  cliWrapper(rotateEnrollEnvironment),
						},
						{
							Name:    "expire-enroll",
							Aliases: []string{"f"},
							Usage:   "Expire the existing enroll URL for a TLS environment",
							Action:  cliWrapper(expireEnrollEnvironment),
						},
						{
							Name:    "notexpire-enroll",
							Aliases: []string{"f"},
							Usage:   "Set the existing enroll URL for a TLS environment to NOT expire",
							Action:  cliWrapper(notexpireEnrollEnvironment),
						},
						{
							Name:    "quick-remove",
							Aliases: []string{"Q"},
							Usage:   "Generates one-liner for quick removing nodes to a TLS environment",
							Flags: []cli.Flag{
								&cli.StringFlag{
									Name:    "target",
									Aliases: []string{"t"},
									Value:   "sh",
									Usage:   "Type of one-liner script",
								},
								&cli.BoolFlag{
									Name:    "insecure",
									Aliases: []string{"i"},
									Value:   false,
									Usage:   "Generate insecure one-liner, without HTTPS",
								},
							},
							Action: cliWrapper(quickRemoveEnvironment),
						},
						{
							Name:    "extend-remove",
							Aliases: []string{"f"},
							Usage:   "Extend the existing enroll URL for a TLS environment",
							Action:  cliWrapper(extendRemoveEnvironment),
						},
						{
							Name:    "rotate-remove",
							Aliases: []string{"f"},
							Usage:   "Rotate to a new enroll URL for a TLS environment",
							Action:  cliWrapper(rotateRemoveEnvironment),
						},
						{
							Name:    "expire-remove",
							Aliases: []string{"f"},
							Usage:   "Expire the existing remove URL for a TLS environment",
							Action:  cliWrapper(expireRemoveEnvironment),
						},
						{
							Name:    "notexpire-remove",
							Aliases: []string{"f"},
							Usage:   "Set the existing remove URL for a TLS environment to NOT expire",
							Action:  cliWrapper(notexpireRemoveEnvironment),
						},
						{
							Name:    "secret",
							Aliases: []string{"x"},
							Usage:   "Output the secret to enroll nodes in an environment",
							Action:  cliWrapper(secretEnvironment),
						},
						{
							Name:    "certificate",
							Aliases: []string{"c", "cert"},
							Usage:   "Output the certificate to enroll nodes in an environment",
							Action:  cliWrapper(certificateEnvironment),
						},
					},
					Usage: "Node enroll actions for an environment",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Value:   "",
							Usage:   "Environment name to be updated",
						},
					},
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
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List all existing TLS environments",
					Action:  cliWrapper(listEnvironment),
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
					Name:    "tag",
					Aliases: []string{"t"},
					Usage:   "Tag an existing node",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "uuid, u",
							Aliases: []string{"u"},
							Usage:   "Node UUID to be tagged",
						},
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Tag name to be used. It will be created if does not exist",
						},
						&cli.StringFlag{
							Name:    "tag-type",
							Aliases: []string{"type"},
							Value:   "custom",
							Usage:   "Tag type to be used. It can be 'env', 'uuid', 'localname' and 'custom'",
						},
					},
					Action: cliWrapper(tagNode),
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
					Name:    "expire",
					Aliases: []string{"e"},
					Usage:   "Mark an on-demand query as expired",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Query name to be expired",
						},
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
						},
					},
					Action: cliWrapper(expireQuery),
				},
				{
					Name:    "run",
					Aliases: []string{"r"},
					Usage:   "Start a new on-demand query",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "query",
							Aliases: []string{"q"},
							Usage:   "Query to be issued",
						},
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
						},
						&cli.StringFlag{
							Name:    "uuid",
							Aliases: []string{"u"},
							Usage:   "Node UUID to be used",
						},
						&cli.BoolFlag{
							Name:    "hidden",
							Aliases: []string{"x"},
							Hidden:  false,
							Usage:   "Mark query as hidden",
						},
						&cli.IntFlag{
							Name:    "expiration",
							Aliases: []string{"E"},
							Value:   6,
							Usage:   "Expiration in hours (0 for no expiration)",
						},
					},
					Action: cliWrapper(runQuery),
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List on-demand queries",
					Flags: []cli.Flag{
						&cli.BoolFlag{
							Name:    "all",
							Aliases: []string{"A"},
							Hidden:  false,
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
						&cli.BoolFlag{
							Name:    "hidden",
							Aliases: []string{"x"},
							Hidden:  false,
							Usage:   "Show hidden queries",
						},
						&cli.BoolFlag{
							Name:    "expired",
							Aliases: []string{"E"},
							Hidden:  false,
							Usage:   "Show expired queries",
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
			Name:  "carve",
			Usage: "Commands for file carves",
			Subcommands: []*cli.Command{
				{
					Name:    "complete",
					Aliases: []string{"c"},
					Usage:   "Mark an file carve query as completed",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Carve name to be completed",
						},
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
						},
					},
					Action: cliWrapper(completeCarve),
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Mark a file carve query as deleted",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Carve name to be deleted",
						},
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
						},
					},
					Action: cliWrapper(deleteCarve),
				},
				{
					Name:    "expire",
					Aliases: []string{"e"},
					Usage:   "Mark a file carve query as expired",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "name",
							Aliases: []string{"n"},
							Usage:   "Carve name to be expired",
						},
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
						},
					},
					Action: cliWrapper(expireCarve),
				},
				{
					Name:    "run",
					Aliases: []string{"r"},
					Usage:   "Start a new carve for a file or a directory",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "path",
							Aliases: []string{"p"},
							Usage:   "File or directory path to be carved",
						},
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
						},
						&cli.StringFlag{
							Name:    "uuid",
							Aliases: []string{"u"},
							Usage:   "Node UUID to be used",
						},
						&cli.IntFlag{
							Name:    "expiration",
							Aliases: []string{"E"},
							Value:   6,
							Usage:   "Expiration in hours (0 for no expiration)",
						},
					},
					Action: cliWrapper(runCarve),
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List file carves",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
						},
					},
					Action: cliWrapper(listCarves),
				},
				{
					Name:    "list-queries",
					Aliases: []string{"l"},
					Usage:   "List file carves queries",
					Flags: []cli.Flag{
						&cli.BoolFlag{
							Name:    "all",
							Aliases: []string{"A"},
							Hidden:  false,
							Usage:   "Show all file carves queries",
						},
						&cli.BoolFlag{
							Name:    "active",
							Aliases: []string{"a"},
							Hidden:  false,
							Usage:   "Show active file carves queries",
						},
						&cli.BoolFlag{
							Name:    "completed",
							Aliases: []string{"c"},
							Hidden:  false,
							Usage:   "Show completed file carves queries",
						},
						&cli.BoolFlag{
							Name:    "expired",
							Aliases: []string{"E"},
							Hidden:  false,
							Usage:   "Show expired file carves queries",
						},
						&cli.BoolFlag{
							Name:    "deleted",
							Aliases: []string{"d"},
							Hidden:  false,
							Usage:   "Show deleted file carves queries",
						},
						&cli.StringFlag{
							Name:    "env",
							Aliases: []string{"e"},
							Usage:   "Environment to be used",
						},
					},
					Action: cliWrapper(listCarveQueries),
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
							Usage:   "Tage name to be used",
						},
						&cli.StringFlag{
							Name:    "env-uuid",
							Aliases: []string{"e"},
							Usage:   "Environment UUID to be used",
						},
						&cli.StringFlag{
							Name:    "icon",
							Aliases: []string{"i"},
							Value:   tags.DefaultTagIcon,
							Usage:   "Fontawesome icon to be used",
						},
						&cli.StringFlag{
							Name:    "color",
							Aliases: []string{"c"},
							Usage:   "HTML color to be used. If not provided it will be randomly generated",
						},
						&cli.StringFlag{
							Name:    "description, d",
							Aliases: []string{"d"},
							Usage:   "Tag description to be used",
						},
						&cli.StringFlag{
							Name:    "tag-type",
							Aliases: []string{"t", "type"},
							Value:   "custom",
							Usage:   "Tag type to be used. It can be 'env', 'uuid', 'platform', 'localname' and 'custom'",
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
							Usage:   "Tage name to be used",
						},
						&cli.StringFlag{
							Name:    "env-uuid",
							Aliases: []string{"e"},
							Usage:   "Environment UUID to be used",
						},
						&cli.StringFlag{
							Name:    "icon",
							Aliases: []string{"i"},
							Usage:   "Fontawesome icon to be used",
						},
						&cli.StringFlag{
							Name:    "color",
							Aliases: []string{"c"},
							Usage:   "HTML color to be used. If not provided it will be randomly generated",
						},
						&cli.StringFlag{
							Name:    "description, d",
							Aliases: []string{"d"},
							Usage:   "Tag description to be used",
						},
						&cli.StringFlag{
							Name:    "tag-type",
							Aliases: []string{"t", "type"},
							Usage:   "Tag type to be used. It can be 'env', 'uuid', 'platform', 'localname' and 'custom'",
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
						&cli.StringFlag{
							Name:    "env-uuid",
							Aliases: []string{"e"},
							Usage:   "Environment UUID to be used",
						},
					},
					Action: cliWrapper(deleteTag),
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List all tags by environment",
					Flags: []cli.Flag{
						&cli.StringFlag{
							Name:    "env-uuid",
							Aliases: []string{"e"},
							Usage:   "Environment UUID to be used",
						},
					},
					Action: cliWrapper(listTagsByEnv),
				},
				{
					Name:    "list-all",
					Aliases: []string{"L"},
					Usage:   "List all tags in osctrl",
					Action:  cliWrapper(listAllTags),
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
						&cli.StringFlag{
							Name:    "env-uuid",
							Aliases: []string{"e"},
							Usage:   "Environment UUID to be used",
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
		{
			Name:  "login",
			Usage: "Login into API and generate JSON config file with token",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "username",
					Aliases: []string{"u"},
					Usage:   "User to be used in login",
				},
				&cli.StringFlag{
					Name:    "environment",
					Aliases: []string{"e"},
					Usage:   "Environment to be used in login",
				},
				&cli.IntFlag{
					Name:    "expiration",
					Aliases: []string{"E"},
					Value:   6,
					Usage:   "Expiration in hours (0 for server default)",
				},
				&cli.BoolFlag{
					Name:        "write-api-file",
					Aliases:     []string{"w"},
					Destination: &writeApiFileFlag,
					Usage:       "Write API configuration to JSON file",
				},
			},
			Action: loginAPI,
		},
	}
	// Initialize formats values
	formats = make(map[string]bool)
	formats[prettyFormat] = true
	formats[jsonFormat] = true
	formats[csvFormat] = true
}

// Action for the DB check
func checkDB(c *cli.Context) error {
	if dbFlag && dbConfigFile != "" {
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
	if !silentFlag {
		fmt.Println("✅ DB check successful")
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
	if !silentFlag {
		fmt.Println("✅ API check successful")
	}
	// Should be good
	return nil
}

// Action for the API login
func loginAPI(c *cli.Context) error {
	// API URL can is needed
	if apiConfig.URL == "" {
		fmt.Println("❌ API URL is required")
		os.Exit(1)
	}
	// Initialize API
	osctrlAPI = CreateAPI(apiConfig, insecureFlag)
	// We need credentials
	username := c.String("username")
	if username == "" {
		fmt.Println("❌ username is required")
		os.Exit(1)
	}
	env := c.String("environment")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	expHours := c.Int("expiration")
	fmt.Printf("\n ->  Please introduce your password: ")
	passwordByte, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return fmt.Errorf("error reading password %s", err)
	}
	fmt.Println()
	apiResponse, err := osctrlAPI.PostLogin(env, username, string(passwordByte), expHours)
	if err != nil {
		return fmt.Errorf("error in login %s", err)
	}
	apiConfig.Token = apiResponse.Token
	if !silentFlag {
		fmt.Printf("\n✅ API Login successful: %s\n", apiResponse.Token)
	}
	if writeApiFileFlag {
		if err := writeAPIConfiguration(apiConfigFile, apiConfig); err != nil {
			return fmt.Errorf("error writing to file %s, %s", apiConfigFile, err)
		}
		if !silentFlag {
			fmt.Printf("\n✅ API config file written: %s\n", apiConfigFile)
		}
	}
	// Should be good
	return nil
}

// Function to wrap actions
func cliWrapper(action func(*cli.Context) error) func(*cli.Context) error {
	return func(c *cli.Context) error {
		// Verify if format is correct
		if !formats[formatFlag] {
			return fmt.Errorf("invalid format %s", formatFlag)
		}
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
			// Initialize carves
			filecarves = carves.CreateFileCarves(db.Conn, settings.CarverDB, nil)
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
			log.Fatal().Msgf("❌ Error with CLI help - %s", err)
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
		log.Fatal().Msgf("❌ Failed to execute - %v", err)
	}
}
