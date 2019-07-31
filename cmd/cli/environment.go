package main

import (
	"fmt"
	"os"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli"
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
	// Get configuration
	var configuration string
	confFile := c.String("configuration")
	if confFile != "" {
		configuration = environments.ReadExternalFile(confFile)
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
		newEnv.Configuration = configuration
		newEnv.Certificate = certificate
		newEnv.EnrollExpire = time.Now().Add(time.Duration(environments.DefaultLinkExpire) * time.Hour)
		newEnv.RemoveExpire = time.Now().Add(time.Duration(environments.DefaultLinkExpire) * time.Hour)
		if err := envs.Create(newEnv); err != nil {
			return err
		}
	} else {
		fmt.Printf("Environment %s already exists!\n", envName)
		os.Exit(1)
	}
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
	fmt.Println(" Configuration: ")
	fmt.Printf("%s\n", env.Configuration)
	fmt.Println(" Certificate: ")
	fmt.Printf("%s\n", env.Certificate)
	fmt.Println()
	return nil
}

func listEnvironment(c *cli.Context) error {
	envAll, err := envs.All()
	if err != nil {
		return err
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader([]string{
		"Name",
		"Type",
		"Hostname",
		"DebugHTTP?",
	})
	if len(envAll) > 0 {
		data := [][]string{}
		for _, env := range envAll {
			e := []string{
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
	if c.String("target") == "sh" {
		oneLiner, _ = environments.QuickAddOneLinerShell(env)
	} else if c.String("target") == "ps1" {
		oneLiner, _ = environments.QuickAddOneLinerPowershell(env)
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
	env, err := envs.Get(envName)
	if err != nil {
		return err
	}
	secret := c.String("secret")
	if secret == "" {
		fmt.Println("Secret file path is required")
		os.Exit(1)
	}
	cert := c.String("certificate")
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
