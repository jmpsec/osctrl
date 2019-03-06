package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/javuto/osctrl/configuration"
	"github.com/javuto/osctrl/context"
	"github.com/javuto/osctrl/nodes"
	"github.com/javuto/osctrl/queries"
	"github.com/javuto/osctrl/users"

	"github.com/jinzhu/gorm"
	"github.com/spf13/viper"
	"github.com/urfave/cli"
)

const (
	// Service configuration file
	defConfigFile = "config/tls.json"
	// Project name
	projectName = "osctrl"
	// Application name
	appName = projectName + "-cli"
	// Application version
	appVersion = "0.0.1"
	// Application usage
	appUsage = "CLI for " + projectName
	// Application description
	appDescription = appUsage + ", a fast and efficient operative system management"
)

// Global variables
var (
	db         *gorm.DB
	dbConfig   DBConf
	app        *cli.App
	configFile string
	config     *configuration.Configuration
	nodesmgr   *nodes.NodeManager
	queriesmgr *queries.Queries
	adminUsers *users.UserManager
	ctxs       *context.Context
)

// Function to load the configuration file and assign to variables
func loadConfiguration() error {
	// Load file and read config
	viper.SetConfigFile(configFile)
	err := viper.ReadInConfig()
	if err != nil {
		return err
	}
	// Backend values
	dbRaw := viper.Sub("db")
	err = dbRaw.Unmarshal(&dbConfig)
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
			Name:  "context",
			Usage: "Commands for TLS context",
			Subcommands: []cli.Command{
				{
					Name:    "add",
					Aliases: []string{"a"},
					Usage:   "Add a new TLS context",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Context to be added",
						},
						cli.StringFlag{
							Name:  "hostname, host",
							Usage: "Context host to be added",
						},
						cli.BoolFlag{
							Name:   "debug, d",
							Hidden: false,
							Usage:  "Context debug capability",
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
					Action: addContext,
				},
				{
					Name:    "delete",
					Aliases: []string{"d"},
					Usage:   "Delete an existing TLS context",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Context to be deleted",
						},
					},
					Action: deleteContext,
				},
				{
					Name:    "show",
					Aliases: []string{"s"},
					Usage:   "Show a TLS context",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Context to be displayed",
						},
					},
					Action: showContext,
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List all existing TLS contexts",
					Action:  listContext,
				},
				{
					Name:  "quick-add",
					Usage: "Generates one-liner for quick adding nodes to context",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:  "name, n",
							Usage: "Context to be used",
						},
						cli.StringFlag{
							Name:  "target, t",
							Value: "sh",
							Usage: "Type of one-liner",
						},
					},
					Action: quickAddContext,
				},
			},
		},
		{
			Name:  "configuration",
			Usage: "Commands for configuration",
			Subcommands: []cli.Command{
				{
					Name:    "add",
					Aliases: []string{"a"},
					Usage:   "Add a new configuration value",
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
					},
					Action: func(c *cli.Context) error {
						// Get values from flags
						name := c.String("name")
						if name == "" {
							fmt.Println("name is required")
							os.Exit(1)
						}
						service := c.String("service")
						if service == "" {
							fmt.Println("service is required")
							os.Exit(1)
						}
						typeValue := c.String("type")
						if typeValue == "" {
							fmt.Println("type is required")
							os.Exit(1)
						}
						values := make(map[string]interface{})
						values[configuration.TypeString] = c.String("string")
						values[configuration.TypeInteger] = c.Int64("integer")
						values[configuration.TypeBoolean] = c.Bool("boolean")
						return config.NewValue(service, name, typeValue, values)
					},
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
					},
					Action: func(c *cli.Context) error {
						// Get values from flags
						name := c.String("name")
						if name == "" {
							fmt.Println("name is required")
							os.Exit(1)
						}
						service := c.String("service")
						if service == "" {
							fmt.Println("service is required")
							os.Exit(1)
						}
						typeValue := c.String("type")
						if typeValue == "" {
							fmt.Println("type is required")
							os.Exit(1)
						}
						var err error
						switch typeValue {
						case configuration.TypeInteger:
							err = config.SetInteger(c.Int64("integer"), service, name)
						case configuration.TypeBoolean:
							err = config.SetBoolean(c.Bool("true"), service, name)
						case configuration.TypeString:
							err = config.SetString(c.String("string"), service, name)
						}
						return err
					},
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
					Action: func(c *cli.Context) error {
						// Get values from flags
						name := c.String("name")
						if name == "" {
							fmt.Println("name is required")
							os.Exit(1)
						}
						service := c.String("service")
						if service == "" {
							fmt.Println("service is required")
							os.Exit(1)
						}
						return config.DeleteValue(service, name)
					},
				},
				{
					Name:    "show",
					Aliases: []string{"s"},
					Usage:   "Show all configuration values",
					Action: func(c *cli.Context) error {
						values, err := config.RetrieveAllValues()
						if err != nil {
							return err
						}
						if len(values) > 0 {
							fmt.Printf("Configuration values:\n\n")
							for _, v := range values {
								fmt.Printf(" Name: %s\n", v.Name)
								fmt.Printf(" Service: %s\n", v.Service)
								fmt.Printf(" Type: %s\n", v.Type)
								fmt.Printf(" String: %s\n", v.String)
								fmt.Printf(" Integer: %d\n", v.Integer)
								fmt.Printf(" Boolean: %v\n", v.Boolean)
								fmt.Println()
							}
						} else {
							fmt.Printf("No configuration values\n")
						}
						return nil
					},
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
					Action: func(c *cli.Context) error {
						// Get values from flags
						uuid := c.String("uuid")
						if uuid == "" {
							fmt.Println("uuid is required")
							os.Exit(1)
						}
						return nodesmgr.ArchiveDeleteByUUID(uuid)
					},
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
					Action: func(c *cli.Context) error {
						// Get values from flags
						target := "active"
						if c.Bool("all") {
							target = "all"
						}
						if c.Bool("inactive") {
							target = "inactive"
						}
						nodes, err := nodesmgr.Gets(target)
						if err != nil {
							return err
						}
						if len(nodes) > 0 {
							fmt.Printf("Existing %s nodes (%d):\n", target, len(nodes))
							for _, n := range nodes {
								fmt.Printf("  Hostname: %s\n", n.Hostname)
								fmt.Printf("  UUID: %s\n", n.UUID)
								fmt.Printf("  Platform: %s\n", n.Platform)
								fmt.Printf("  Context: %s\n", n.Context)
								fmt.Println()
							}
						} else {
							fmt.Printf("No nodes\n")
						}
						return nil
					},
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
					Action: func(c *cli.Context) error {
						// Get values from flags
						name := c.String("name")
						if name == "" {
							fmt.Println("name is required")
							os.Exit(1)
						}
						return queriesmgr.Complete(name)
					},
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
					Action: func(c *cli.Context) error {
						// Get values from flags
						name := c.String("name")
						if name == "" {
							fmt.Println("name is required")
							os.Exit(1)
						}
						return queriesmgr.Delete(name)
					},
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
					Action: func(c *cli.Context) error {
						// Get values from flags
						target := "all"
						if c.Bool("all") {
							target = "all"
						}
						if c.Bool("active") {
							target = "active"
						}
						if c.Bool("completed") {
							target = "completed"
						}
						if c.Bool("deleted") {
							target = "deleted"
						}
						qs, err := queriesmgr.Gets(target)
						if err != nil {
							return err
						}
						if len(qs) > 0 {
							fmt.Printf("Existing %s queries (%d):\n", target, len(qs))
							for _, q := range qs {
								fmt.Printf("  Name: %s\n", q.Name)
								fmt.Printf("  Creator: %s\n", q.Creator)
								fmt.Printf("  Query: %s\n", q.Query)
								fmt.Println()
							}
						} else {
							fmt.Printf("No nodes\n")
						}
						return nil
					},
				},
			},
		},
	}
	// Load configuration
	err = loadConfiguration()
	if err != nil {
		panic(err)
	}
}

// Go go!
func main() {
	// Database handler
	db = getDB()
	// Close when exit
	defer db.Close()
	// Automigrate tables
	if err := automigrateDB(); err != nil {
		log.Fatalf("Failed to AutoMigrate: %v", err)
	}
	// Initialize users
	adminUsers = users.CreateUserManager(db)
	// Initialize context
	ctxs = context.CreateContexts(db)
	// Initialize configuration
	config = configuration.NewConfiguration(db)
	// Initialize nodes
	nodesmgr = nodes.CreateNodes(db)
	// Initialize queries
	queriesmgr = queries.CreateQueries(db)
	// Let's go!
	err := app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}
