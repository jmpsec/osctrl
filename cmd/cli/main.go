package main

import (
	"log"
	"os"
	"path/filepath"

	"github.com/javuto/osctrl/pkg/environments"
	"github.com/javuto/osctrl/pkg/nodes"
	"github.com/javuto/osctrl/pkg/queries"
	"github.com/javuto/osctrl/pkg/settings"
	"github.com/javuto/osctrl/pkg/users"

	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"
	"github.com/urfave/cli"
)

const (
	// Service configuration file
	defConfigFile string = "config/tls.json"
	// DB configuration file
	defDBConfigurationFile string = "config/db.json"
	// Project name
	projectName string = "osctrl"
	// Application name
	appName string = projectName + "-cli"
	// Application version
	appVersion string = "0.1.2"
	// Application usage
	appUsage string = "CLI for " + projectName
	// Application description
	appDescription string = appUsage + ", a fast and efficient operative system management"
)

// Global variables
var (
	db           *gorm.DB
	app          *cli.App
	configFile   string
	dbConfigFile string
	dbConfig     JSONConfigurationDB
	settingsmgr  *settings.Settings
	nodesmgr     *nodes.NodeManager
	queriesmgr   *queries.Queries
	adminUsers   *users.UserManager
	envs         *environments.Environment
)

// Function to load the configuration file and assign to variables
func loadConfiguration() error {
	// Load file and read config
	viper.SetConfigFile(configFile)
	err := viper.ReadInConfig()
	if err != nil {
		return err
	}
	// No errors!
	return nil
}

// Initialization code
func init() {
	// Get path of process
	executableProcess, err := os.Executable()
	if err != nil {
		panic(err)
	}
	configFile = filepath.Dir(executableProcess) + "/" + defConfigFile
	dbConfigFile = filepath.Dir(executableProcess) + "/" + defDBConfigurationFile
	// Initialize CLI details
	app = cli.NewApp()
	app.Name = appName
	app.Usage = appUsage
	app.Version = appVersion
	app.Description = appDescription
	// Flags
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "config, c",
			Value:       configFile,
			Usage:       "Load TLS configuration from `FILE`",
			EnvVar:      "TLS_CONFIG",
			Destination: &configFile,
		},
		cli.StringFlag{
			Name:        "db, d",
			Value:       dbConfigFile,
			Usage:       "Load DB configuration from `FILE`",
			EnvVar:      "DB_CONFIG",
			Destination: &dbConfigFile,
		},
	}
	// Commands
	app.Commands = []cli.Command{
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
							Name:  "fullname, n",
							Usage: "Full name for the new user",
						},
					},
					Action: addUser,
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
					},
					Action: editUser,
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
					Action: deleteUser,
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List all existing users",
					Action:  listUsers,
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
							Name:  "configuration, conf",
							Usage: "Configuration file to be read",
						},
						cli.StringFlag{
							Name:  "certificate, crt",
							Usage: "Certificate file to be read",
						},
					},
					Action: addEnvironment,
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
					Action: deleteEnvironment,
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
					Action: showEnvironment,
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List all existing TLS environments",
					Action:  listEnvironment,
				},
				{
					Name:  "quick-add",
					Usage: "Generates one-liner for quick adding nodes to environment",
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
					Action: quickAddEnvironment,
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
					Action: addSetting,
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
					Action: updateSetting,
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
					Action: deleteSetting,
				},
				{
					Name:    "show",
					Aliases: []string{"s"},
					Usage:   "Show all configuration values",
					Action:  listConfiguration,
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
					Action: deleteNode,
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
					Action: listNodes,
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
					Action: completeQuery,
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
					Action: deleteQuery,
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
					Action: listQueries,
				},
			},
		},
	}
	// Load configuration
	if err := loadConfiguration(); err != nil {
		log.Fatalf("Error loading configuration %s", err)
	}
	// Load DB configuration
	dbConfig, err = loadDBConfiguration(dbConfigFile)
	if err != nil {
		log.Fatalf("Error loading DB configuration %s", err)
	}
}

// Go go!
func main() {
	// Database handler
	db = getDB(dbConfig)
	// Close when exit
	//defer db.Close()
	defer func() {
		err := db.Close()
		if err != nil {
			log.Fatalf("Failed to close Database handler %v", err)
		}
	}()
	// Initialize users
	adminUsers = users.CreateUserManager(db)
	// Initialize environment
	envs = environments.CreateEnvironment(db)
	// Initialize settings
	settingsmgr = settings.NewSettings(db)
	// Initialize nodes
	nodesmgr = nodes.CreateNodes(db)
	// Initialize queries
	queriesmgr = queries.CreateQueries(db)
	// Let's go!
	if err := app.Run(os.Args); err != nil {
		log.Fatalf("Failed to execute %v", err)
	}
}
