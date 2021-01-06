package main

import (
	"fmt"
	"os"
	"time"

	"github.com/jmpsec/osctrl/environments"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
)

const (
	targetShell      = "sh"
	targetPowershell = "ps1"
	optionTypeString = "string"
	optionTypeInt    = "int"
	optionTypeBool   = "bool"
)

func addEnvironment(c *cli.Context) error {
	// Get environment name
	envName := c.String("name")
	if envName == "" {
		fmt.Println("Environment name is required")
		os.Exit(1)
	}
	// Get environment hostname
	envHost := c.String("hostname")
	if envHost == "" {
		fmt.Println("Environment hostname is required")
		os.Exit(1)
	}
	// Get certificate
	var certificate string
	certFile := c.String("certificate")
	if certFile != "" {
		certificate = environments.ReadExternalFile(certFile)
	}
	// Create environment if it does not exist
	if !envs.Exists(envName) {
		newEnv := envs.Empty(envName, envHost)
		newEnv.DebugHTTP = c.Bool("debug")
		newEnv.Configuration = envs.GenEmptyConfiguration(true)
		newEnv.Certificate = certificate
		newEnv.EnrollExpire = time.Now().Add(time.Duration(environments.DefaultLinkExpire) * time.Hour)
		newEnv.RemoveExpire = time.Now().Add(time.Duration(environments.DefaultLinkExpire) * time.Hour)
		if err := envs.Create(newEnv); err != nil {
			return err
		}
		// Update configuration parts from serialized
		cnf, err := envs.GenStructConf([]byte(newEnv.Configuration))
		if err != nil {
			return err
		}
		if err := envs.UpdateConfigurationParts(envName, cnf); err != nil {
			return err
		}
		// Create a tag for this new environment
		if err := tagsmgr.NewTag(newEnv.Name, "Tag for environment "+newEnv.Name, "", newEnv.Icon); err != nil {
			return err
		}
		// Generate flags
		flags, err := environments.GenerateFlags(newEnv, "", "")
		if err != nil {
			return err
		}
		// Update flags in the newly created environment
		if err := envs.UpdateFlags(envName, flags); err != nil {
			return err
		}
	} else {
		fmt.Printf("Environment %s already exists!\n", envName)
		os.Exit(1)
	}
	fmt.Printf("Environment %s was created successfully\n", envName)
	return nil
}

func updateEnvironment(c *cli.Context) error {
	// Get environment name
	envName := c.String("name")
	if envName == "" {
		fmt.Println("Environment name is required")
		os.Exit(1)
	}
	env, err := envs.Get(envName)
	if err != nil {
		return err
	}
	debug := c.Bool("debug")
	env.DebugHTTP = debug
	hostname := c.String("hostname")
	if hostname != "" {
		env.Hostname = hostname
	}
	// Intervals
	loggingInterval := c.Int("logging")
	if loggingInterval != 0 {
		env.LogInterval = loggingInterval
	}
	configInterval := c.Int("config")
	if loggingInterval != 0 {
		env.ConfigInterval = configInterval
	}
	queryInterval := c.Int("query")
	if loggingInterval != 0 {
		env.QueryInterval = queryInterval
	}
	// Update environment
	if err := envs.Update(env); err != nil {
		return err
	}
	// Make sure flags are up to date
	flags, err := environments.GenerateFlags(env, "", "")
	if err != nil {
		return err
	}
	// Update flags in the newly created environment
	if err := envs.UpdateFlags(envName, flags); err != nil {
		return err
	}
	fmt.Printf("Environment %s was updated successfully\n", envName)
	return nil
}

func deleteEnvironment(c *cli.Context) error {
	// Get environment name
	envName := c.String("name")
	if envName == "" {
		fmt.Println("Environment name is required")
		os.Exit(1)
	}
	return envs.Delete(envName)
}

func showEnvironment(c *cli.Context) error {
	// Get environment name
	envName := c.String("name")
	if envName == "" {
		fmt.Println("Environment name is required")
		os.Exit(1)
	}
	env, err := envs.Get(envName)
	if err != nil {
		return err
	}
	fmt.Printf(" UUID: %s\n", env.UUID)
	fmt.Printf(" Name: %s\n", env.Name)
	fmt.Printf(" Host: %s\n", env.Hostname)
	fmt.Printf(" Secret: %s\n", env.Secret)
	fmt.Printf(" EnrollExpire: %v\n", env.EnrollExpire)
	fmt.Printf(" EnrollSecretPath: %s\n", env.EnrollSecretPath)
	fmt.Printf(" RemoveExpire: %v\n", env.RemoveExpire)
	fmt.Printf(" RemoveSecretPath: %s\n", env.RemoveSecretPath)
	fmt.Printf(" Type: %v\n", env.Type)
	fmt.Printf(" DebugHTTP? %v\n", env.DebugHTTP)
	fmt.Printf(" Icon: %s\n", env.Icon)
	fmt.Printf(" Configuration Path: /%s/%s\n", env.Name, env.ConfigPath)
	fmt.Printf(" Configuration Interval: %d seconds\n", env.ConfigInterval)
	fmt.Printf(" Logging Path: /%s/%s\n", env.Name, env.LogPath)
	fmt.Printf(" Logging Interval: %d seconds\n", env.LogInterval)
	fmt.Printf(" Query Read Path: /%s/%s\n", env.Name, env.QueryReadPath)
	fmt.Printf(" Query Write Path: /%s/%s\n", env.Name, env.QueryWritePath)
	fmt.Printf(" Query Interval: %d seconds\n", env.QueryInterval)
	fmt.Printf(" Carve Init Path: /%s/%s\n", env.Name, env.CarverInitPath)
	fmt.Printf(" Carve Block Path: /%s/%s\n", env.Name, env.CarverBlockPath)
	fmt.Println(" Flags: ")
	fmt.Printf("%s\n", env.Flags)
	fmt.Println(" Options: ")
	fmt.Printf("%s\n", env.Options)
	fmt.Println(" Schedule: ")
	fmt.Printf("%s\n", env.Schedule)
	fmt.Println(" Packs: ")
	fmt.Printf("%s\n", env.Packs)
	fmt.Println(" Decorators: ")
	fmt.Printf("%s\n", env.Decorators)
	fmt.Println(" ATC: ")
	fmt.Printf("%s\n", env.ATC)
	fmt.Println(" Configuration: ")
	fmt.Printf("%s\n", env.Configuration)
	fmt.Println(" Certificate: ")
	fmt.Printf("%s\n", env.Certificate)
	fmt.Println()
	return nil
}

func showFlagsEnvironment(c *cli.Context) error {
	// Get environment name
	envName := c.String("name")
	if envName == "" {
		fmt.Println("Environment name is required")
		os.Exit(1)
	}
	env, err := envs.Get(envName)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", env.Flags)
	return nil
}

func listEnvironment(c *cli.Context) error {
	envAll, err := envs.All()
	if err != nil {
		return err
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{
		"UUID",
		"Name",
		"Type",
		"Hostname",
		"DebugHTTP?",
	})
	if len(envAll) > 0 {
		data := [][]string{}
		for _, env := range envAll {
			e := []string{
				env.UUID,
				env.Name,
				env.Type,
				env.Hostname,
				stringifyBool(env.DebugHTTP),
			}
			data = append(data, e)
		}
		table.AppendBulk(data)
		table.Render()
	} else {
		fmt.Printf("No environments\n")
	}
	return nil
}

func quickAddEnvironment(c *cli.Context) error {
	// Get environment name
	envName := c.String("name")
	if envName == "" {
		fmt.Println("Environment name is required")
		os.Exit(1)
	}
	env, err := envs.Get(envName)
	if err != nil {
		return err
	}
	var oneLiner string
	switch c.String("target") {
	case targetShell:
		oneLiner, _ = environments.QuickAddOneLinerShell(env)
	case targetPowershell:
		oneLiner, _ = environments.QuickAddOneLinerPowershell(env)
	default:
		fmt.Printf("Invalid target! It can be %s or %s\n", targetShell, targetPowershell)
		os.Exit(1)
	}
	fmt.Printf("%s\n", oneLiner)
	return nil
}

func flagsEnvironment(c *cli.Context) error {
	// Get environment name
	envName := c.String("name")
	if envName == "" {
		fmt.Println("Environment name is required")
		os.Exit(1)
	}
	secret := c.String("secret")
	cert := c.String("certificate")
	env, err := envs.Get(envName)
	if err != nil {
		return err
	}
	flags, err := environments.GenerateFlags(env, secret, cert)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", flags)
	return nil
}

func secretEnvironment(c *cli.Context) error {
	// Get environment name
	envName := c.String("name")
	if envName == "" {
		fmt.Println("Environment name is required")
		os.Exit(1)
	}
	env, err := envs.Get(envName)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", env.Secret)
	return nil
}

func addScheduledQuery(c *cli.Context) error {
	// Get environment name
	envName := c.String("name")
	if envName == "" {
		fmt.Println("Environment name is required")
		os.Exit(1)
	}
	// Get query name
	queryName := c.String("query-name")
	if queryName == "" {
		fmt.Println("Query name is required")
		os.Exit(1)
	}
	// Get query
	query := c.String("query")
	if query == "" {
		fmt.Println("Query is required")
		os.Exit(1)
	}
	// Get interval
	interval := c.Int("interval")
	if interval == 0 {
		fmt.Println("Interval is required")
		os.Exit(1)
	}
	// Get platform
	platform := c.String("platform")
	// Get version
	version := c.String("version")
	// Add new scheduled query
	qData := environments.ScheduleQuery{
		Query:    query,
		Interval: interval,
		Platform: platform,
		Version:  version,
	}
	if err := envs.AddScheduleConfQuery(envName, queryName, qData); err != nil {
		return err
	}
	fmt.Printf("Query %s was created successfully\n", queryName)
	return nil
}

func addOsqueryOption(c *cli.Context) error {
	// Get environment name
	envName := c.String("name")
	if envName == "" {
		fmt.Println("Environment name is required")
		os.Exit(1)
	}
	// Get option
	option := c.String("option")
	if option == "" {
		fmt.Println("Option is required")
		os.Exit(1)
	}
	// Get option type
	optionType := c.String("type")
	if optionType == "" {
		fmt.Println("Option type is required")
		os.Exit(1)
	}
	// Get option value based on the type
	var optionValue interface{}
	switch c.String("type") {
	case optionTypeBool:
		optionValue = c.Bool("bool-value")
	case optionTypeInt:
		optionValue = c.Int("int-value")
	case optionTypeString:
		optionValue = c.String("string-value")
	default:
		fmt.Printf("Invalid type! It can be %s, %s or %s\n", optionTypeBool, optionTypeInt, optionTypeString)
		os.Exit(1)
	}
	// Add osquery option
	if err := envs.AddOptionsConf(envName, option, optionValue); err != nil {
		return err
	}
	fmt.Printf("Option %s was added successfully\n", option)
	return nil
}
