package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/javuto/osctrl/configuration"
	"github.com/javuto/osctrl/context"
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
	adminUsers *users.UserManager
	contexts   *context.Context
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
	// Initialize users
	adminUsers = users.CreateUserManager(db)
	// Initialize context
	contexts = context.CreateContexts(db)
	// Initialize configuration
	config = configuration.NewConfiguration(db)
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
					Action: func(c *cli.Context) error {
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
					},
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
					Action: func(c *cli.Context) error {
						// Get values from flags
						username := c.String("username")
						if username == "" {
							fmt.Println("username is required")
							os.Exit(1)
						}
						return adminUsers.Delete(username)
					},
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List all existing users",
					Action: func(c *cli.Context) error {
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
					},
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
					Action: func(c *cli.Context) error {
						// Get context name
						ctxName := c.String("name")
						if ctxName == "" {
							fmt.Println("Context name is required")
							os.Exit(1)
						}
						// Get context hostname
						ctxHost := c.String("hostname")
						if ctxHost == "" {
							fmt.Println("Context hostname is required")
							os.Exit(1)
						}
						// Get configuration
						var configuration string
						confFile := c.String("configuration")
						if confFile != "" {
							configuration = context.ReadExternalFile(confFile)
						}
						// Get certificate
						var certificate string
						certFile := c.String("certificate")
						if certFile != "" {
							certificate = context.ReadExternalFile(certFile)
						}
						// Create context if it does not exist
						if !contexts.Exists(ctxName) {
							newContext := contexts.Empty(ctxName, ctxHost)
							newContext.DebugHTTP = c.Bool("debug")
							newContext.Configuration = configuration
							newContext.Certificate = certificate
							if err := contexts.Create(newContext); err != nil {
								return err
							}
						} else {
							fmt.Printf("Context %s already exists!\n", ctxName)
							os.Exit(1)
						}
						return nil
					},
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
					Action: func(c *cli.Context) error {
						// Get context name
						ctxName := c.String("name")
						if ctxName == "" {
							fmt.Println("Context name is required")
							os.Exit(1)
						}
						return contexts.Delete(ctxName)
					},
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
					Action: func(c *cli.Context) error {
						// Get context name
						ctxName := c.String("name")
						if ctxName == "" {
							fmt.Println("Context name is required")
							os.Exit(1)
						}
						ctx, err := contexts.Get(ctxName)
						if err != nil {
							return err
						}
						fmt.Printf("Context %s\n", ctx.Name)
						fmt.Printf(" Name: %s\n", ctx.Name)
						fmt.Printf(" Host: %s\n", ctx.Hostname)
						fmt.Printf(" Secret: %s\n", ctx.Secret)
						fmt.Printf(" SecretPath: %s\n", ctx.SecretPath)
						fmt.Printf(" Type: %v\n", ctx.Type)
						fmt.Printf(" DebugHTTP? %v\n", ctx.DebugHTTP)
						fmt.Printf(" Icon: %s\n", ctx.Icon)
						fmt.Println(" Configuration: ")
						fmt.Printf("%s\n", ctx.Configuration)
						fmt.Println(" Certificate: ")
						fmt.Printf("%s\n", ctx.Certificate)
						fmt.Println()
						return nil
					},
				},
				{
					Name:    "list",
					Aliases: []string{"l"},
					Usage:   "List all existing TLS contexts",
					Action: func(c *cli.Context) error {
						contexts, err := contexts.All()
						if err != nil {
							return err
						}
						if len(contexts) > 0 {
							fmt.Printf("Existing contexts:\n\n")
							for _, ctx := range contexts {
								fmt.Printf("  Name: %s\n", ctx.Name)
							}
							fmt.Println()
						} else {
							fmt.Printf("No contexts\n")
						}
						return nil
					},
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
					Action: func(c *cli.Context) error {
						// Get context name
						ctxName := c.String("name")
						if ctxName == "" {
							fmt.Println("Context name is required")
							os.Exit(1)
						}
						ctx, err := contexts.Get(ctxName)
						if err != nil {
							return err
						}
						var oneLiner string
						if c.String("target") == "sh" {
							oneLiner, _ = contexts.QuickAddOneLinerShell(ctx)
						} else if c.String("target") == "ps1" {
							oneLiner, _ = contexts.QuickAddOneLinerPowershell(ctx)
						}
						fmt.Printf("%s\n", oneLiner)
						return nil
					},
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
						values[typeString] = c.String("string")
						values[typeInteger] = c.Int64("integer")
						values[typeBoolean] = c.Bool("boolean")
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
						case typeInteger:
							err = config.SetInteger(c.Int64("integer"), service, name)
						case typeBoolean:
							err = config.SetBoolean(c.Bool("true"), service, name)
						case typeString:
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
			Name:        "node",
			Usage:       "Commands for nodes",
			Subcommands: []cli.Command{},
		},
		{
			Name:        "query",
			Usage:       "Commands for queries",
			Subcommands: []cli.Command{},
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
	// Service configuration
	var err error
	config, err = NewServiceConfiguration(db)
	if err != nil {
		panic(err)
	}
	// Let's go!
	err = app.Run(os.Args)
	if err != nil {
		panic(err)
	}
}
