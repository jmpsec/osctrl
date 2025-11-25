package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v3"
)

const (
	targetShell      = "sh"
	targetPowershell = "ps1"
	optionTypeString = "string"
	optionTypeInt    = "int"
	optionTypeBool   = "bool"
)

func addEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	// Get environment hostname
	envHost := cmd.String("hostname")
	if envHost == "" {
		fmt.Println("❌ environment hostname is required")
		os.Exit(1)
	}
	// Get certificate
	var certificate string
	certFile := cmd.String("certificate")
	if certFile != "" {
		certificate = environments.ReadExternalFile(certFile)
	}
	// Get osquery values to generate flags
	osqueryValues := config.OsqueryConfiguration{
		Config: cmd.Bool("config"),
		Logger: cmd.Bool("logger"),
		Query:  cmd.Bool("query"),
		Carve:  cmd.Bool("carve"),
	}
	if dbFlag {
		// Create environment if it does not exist
		if !envs.Exists(envName) {
			newEnv := envs.Empty(envName, envHost)
			newEnv.DebugHTTP = cmd.Bool("debug")
			newEnv.Configuration = envs.GenEmptyConfiguration(true)
			newEnv.Certificate = certificate
			newEnv.EnrollExpire = time.Now().Add(time.Duration(environments.DefaultLinkExpire) * time.Hour)
			newEnv.RemoveExpire = time.Now().Add(time.Duration(environments.DefaultLinkExpire) * time.Hour)
			if err := envs.Create(&newEnv); err != nil {
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
			if err := tagsmgr.NewTag(
				newEnv.Name,
				"Tag for environment "+newEnv.Name,
				tags.RandomColor(),
				newEnv.Icon,
				appName,
				newEnv.ID,
				false,
				tags.TagTypeEnv,
				tags.TagCustomEnv); err != nil {
				return err
			}
			// Generate flags
			flags, err := envs.GenerateFlags(newEnv, "", "", osqueryValues)
			if err != nil {
				return err
			}
			// Update flags in the newly created environment
			if err := envs.UpdateFlags(envName, flags); err != nil {
				return err
			}
		} else {
			fmt.Printf("❌ environment %s already exists!\n", envName)
			os.Exit(1)
		}
		// Audit log
		auditlogsmgr.EnvAction(getShellUsername(), "add environment "+envName, "CLI", 0)
		fmt.Printf("✅ environment %s was created successfully\n", envName)
	} else if apiFlag {
		fmt.Println("❌ API not supported yet for this operation")
		os.Exit(1)
	}
	return nil
}

func updateEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	// Get osquery values to generate flags
	osqueryValues := config.OsqueryConfiguration{
		Config: cmd.Bool("config-plugin"),
		Logger: cmd.Bool("logger-plugin"),
		Query:  cmd.Bool("query-plugin"),
		Carve:  cmd.Bool("carve-plugin"),
	}
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		debug := cmd.Bool("debug")
		env.DebugHTTP = debug
		enroll := cmd.Bool("enroll")
		env.AcceptEnrolls = enroll
		hostname := cmd.String("hostname")
		if hostname != "" {
			env.Hostname = hostname
		}
		// Packages
		deb := cmd.String("deb")
		if deb != "" {
			env.DebPackage = deb
		}
		rpm := cmd.String("rpm")
		if rpm != "" {
			env.RpmPackage = rpm
		}
		msi := cmd.String("msi")
		if msi != "" {
			env.MsiPackage = msi
		}
		pkg := cmd.String("pkg")
		if pkg != "" {
			env.PkgPackage = pkg
		}
		// Intervals
		loggingInterval := cmd.Int("logging")
		if loggingInterval != 0 {
			env.LogInterval = loggingInterval
		}
		configInterval := cmd.Int("config")
		if configInterval != 0 {
			env.ConfigInterval = configInterval
		}
		queryInterval := cmd.Int("query")
		if queryInterval != 0 {
			env.QueryInterval = queryInterval
		}
		// Update environment
		if err := envs.Update(env); err != nil {
			return err
		}
		// Make sure flags are up to date
		flags, err := envs.GenerateFlags(env, "", "", osqueryValues)
		if err != nil {
			return err
		}
		// Update flags in the newly created environment
		if err := envs.UpdateFlags(envName, flags); err != nil {
			return err
		}
		// Audit log
		auditlogsmgr.EnvAction(getShellUsername(), "update environment "+envName, "CLI", env.ID)
		fmt.Printf("✅ environment %s was updated successfully\n", envName)
	} else if apiFlag {
		fmt.Println("❌ API not supported yet for this operation")
		os.Exit(1)
	}
	return nil
}

func deleteEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	if dbFlag {
		// Audit log
		auditlogsmgr.EnvAction(getShellUsername(), "delete environment "+envName, "CLI", 0)
		return envs.Delete(envName)
	} else if apiFlag {
		fmt.Println("❌ API not supported yet for this operation")
		os.Exit(1)
	}
	return nil
}

func showEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	var env environments.TLSEnvironment
	if dbFlag {
		env, err = envs.Get(envName)
		if err != nil {
			return err
		}
		// Audit log
		auditlogsmgr.EnvAction(getShellUsername(), "show environment "+envName, "CLI", 0)
	} else if apiFlag {
		env, err = osctrlAPI.GetEnvironment(envName)
		if err != nil {
			return err
		}
	}
	fmt.Printf(" UUID: %s\n", env.UUID)
	fmt.Printf(" Name: %s\n", env.Name)
	fmt.Printf(" Host: %s\n", env.Hostname)
	fmt.Printf(" Secret: %s\n", env.Secret)
	fmt.Printf(" EnrollExpire: %v\n", env.EnrollExpire)
	fmt.Printf(" EnrollSecretPath: %s\n", env.EnrollSecretPath)
	fmt.Printf(" RemoveExpire: %v\n", env.RemoveExpire)
	fmt.Printf(" RemoveSecretPath: %s\n", env.RemoveSecretPath)
	fmt.Printf(" DebPackage: %s\n", env.DebPackage)
	fmt.Printf(" RpmPackage: %s\n", env.RpmPackage)
	fmt.Printf(" MsiPackage: %s\n", env.MsiPackage)
	fmt.Printf(" PkgPackage: %s\n", env.PkgPackage)
	fmt.Printf(" Type: %v\n", env.Type)
	fmt.Printf(" DebugHTTP? %v\n", env.DebugHTTP)
	fmt.Printf(" Icon: %s\n", env.Icon)
	fmt.Printf(" Configuration Path: /%s/%s\n", env.UUID, env.ConfigPath)
	fmt.Printf(" Configuration Interval: %d seconds\n", env.ConfigInterval)
	fmt.Printf(" Logging Path: /%s/%s\n", env.UUID, env.LogPath)
	fmt.Printf(" Logging Interval: %d seconds\n", env.LogInterval)
	fmt.Printf(" Query Read Path: /%s/%s\n", env.UUID, env.QueryReadPath)
	fmt.Printf(" Query Write Path: /%s/%s\n", env.UUID, env.QueryWritePath)
	fmt.Printf(" Query Interval: %d seconds\n", env.QueryInterval)
	fmt.Printf(" Carve Init Path: /%s/%s\n", env.UUID, env.CarverInitPath)
	fmt.Printf(" Carve Block Path: /%s/%s\n", env.UUID, env.CarverBlockPath)
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

func showFlagsEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	var env environments.TLSEnvironment
	if dbFlag {
		env, err = envs.Get(envName)
		if err != nil {
			return err
		}
		// Audit log
		auditlogsmgr.EnvAction(getShellUsername(), "show flags for "+envName, "CLI", 0)
	} else if apiFlag {
		env, err = osctrlAPI.GetEnvironment(envName)
		if err != nil {
			return err
		}
	}
	fmt.Printf("%s\n", env.Flags)
	return nil
}

func newFlagsEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	// Get osquery values to generate flags
	osqueryValues := config.OsqueryConfiguration{
		Config: cmd.Bool("config"),
		Logger: cmd.Bool("logger"),
		Query:  cmd.Bool("query"),
		Carve:  cmd.Bool("carve"),
	}
	if dbFlag {
		flags, err := envs.GenerateFlagsEnv(envName, "", "", osqueryValues)
		if err != nil {
			return err
		}
		if err := envs.UpdateFlags(envName, flags); err != nil {
			return err
		}
	} else if apiFlag {
		fmt.Println("❌ API not supported yet for this operation")
		os.Exit(1)
	}
	return nil
}

func listEnvironment(ctx context.Context, cmd *cli.Command) error {
	var envAll []environments.TLSEnvironment
	if dbFlag {
		envAll, err = envs.All()
		if err != nil {
			return err
		}
	} else if apiFlag {
		envAll, err = osctrlAPI.GetEnvironments()
		if err != nil {
			return err
		}
	}
	table := tablewriter.NewWriter(os.Stdout)
	table.Header("UUID", "Name", "Type", "Hostname", "DebugHTTP?")
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
		table.Bulk(data)
		table.Render()
	} else {
		fmt.Printf("No environments\n")
	}
	return nil
}

func quickAddEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	var env environments.TLSEnvironment
	if dbFlag {
		env, err = envs.Get(envName)
		if err != nil {
			return err
		}
	} else if apiFlag {
		env, err = osctrlAPI.GetEnvironment(envName)
		if err != nil {
			return err
		}
	}
	insecure := (cmd.Bool("insecure") || (env.Certificate != ""))
	var oneLiner string
	switch cmd.String("target") {
	case targetShell:
		oneLiner, _ = environments.QuickAddOneLinerShell(insecure, env)
	case targetPowershell:
		oneLiner, _ = environments.QuickAddOneLinerPowershell(insecure, env)
	default:
		fmt.Printf("❌ invalid target! It can be %s or %s\n", targetShell, targetPowershell)
		os.Exit(1)
	}
	fmt.Printf("%s\n", oneLiner)
	return nil
}

func extendEnrollEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	msg := "enrollment extended successfully"
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		if err := envs.ExtendEnroll(env.UUID); err != nil {
			return err
		}
	} else if apiFlag {
		msg, err = osctrlAPI.ExtendEnrollment(envName)
		if err != nil {
			return err
		}
	}
	fmt.Printf("✅ %s\n", msg)
	return nil
}

func rotateEnrollEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	msg := "enrollment rotated successfully"
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		if err := envs.ExtendEnroll(env.UUID); err != nil {
			return err
		}
	} else if apiFlag {
		msg, err = osctrlAPI.ExtendEnrollment(envName)
		if err != nil {
			return err
		}
	}
	fmt.Printf("✅ %s\n", msg)
	return nil
}

func expireEnrollEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	msg := "enrollment expired successfully"
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		if err := envs.ExpireEnroll(env.UUID); err != nil {
			return err
		}
	} else if apiFlag {
		msg, err = osctrlAPI.ExpireEnrollment(envName)
		if err != nil {
			return err
		}
	}
	fmt.Printf("✅ %s\n", msg)
	return nil
}

func notexpireEnrollEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	msg := "enrollment set to NOT expire"
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		if err := envs.NotExpireEnroll(env.UUID); err != nil {
			return err
		}
	} else if apiFlag {
		msg, err = osctrlAPI.NotexpireEnrollment(envName)
		if err != nil {
			return err
		}
	}
	fmt.Printf("✅ %s\n", msg)
	return nil
}

func quickRemoveEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	var env environments.TLSEnvironment
	if dbFlag {
		env, err = envs.Get(envName)
		if err != nil {
			return err
		}
	} else if apiFlag {
		env, err = osctrlAPI.GetEnvironment(envName)
		if err != nil {
			return err
		}
	}
	insecure := (cmd.Bool("insecure") || (env.Certificate != ""))
	var oneLiner string
	switch cmd.String("target") {
	case targetShell:
		oneLiner, _ = environments.QuickRemoveOneLinerShell(insecure, env)
	case targetPowershell:
		oneLiner, _ = environments.QuickRemoveOneLinerPowershell(insecure, env)
	default:
		fmt.Printf("❌ invalid target! It can be %s or %s\n", targetShell, targetPowershell)
		os.Exit(1)
	}
	fmt.Printf("%s\n", oneLiner)
	return nil
}

func extendRemoveEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	msg := "remove extended successfully"
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		if err := envs.ExtendRemove(env.UUID); err != nil {
			return err
		}
	} else if apiFlag {
		msg, err = osctrlAPI.ExtendRemove(envName)
		if err != nil {
			return err
		}
	}
	fmt.Printf("✅ %s\n", msg)
	return nil
}

func rotateRemoveEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	msg := "remove rotated successfully"
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		if err := envs.RotateRemove(env.UUID); err != nil {
			return err
		}
	} else if apiFlag {
		msg, err = osctrlAPI.RotateRemove(envName)
		if err != nil {
			return err
		}
	}
	fmt.Printf("✅ %s\n", msg)
	return nil
}

func expireRemoveEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	msg := "remove expired successfully"
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		if err := envs.ExpireRemove(env.UUID); err != nil {
			return err
		}
	} else if apiFlag {
		msg, err = osctrlAPI.ExpireRemove(envName)
		if err != nil {
			return err
		}
	}
	fmt.Printf("✅ %s\n", msg)
	return nil
}

func notexpireRemoveEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	msg := "remove set to NOT expire"
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		if err := envs.NotExpireRemove(env.UUID); err != nil {
			return err
		}
	} else if apiFlag {
		msg, err = osctrlAPI.NotexpireRemove(envName)
		if err != nil {
			return err
		}
	}
	fmt.Printf("✅ %s\n", msg)
	return nil
}

func genFlagsEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	secret := cmd.String("secret")
	cert := cmd.String("certificate")
	// Get osquery values to generate flags
	osqueryValues := config.OsqueryConfiguration{
		Config: cmd.Bool("config"),
		Logger: cmd.Bool("logger"),
		Query:  cmd.Bool("query"),
		Carve:  cmd.Bool("carve"),
	}
	var env environments.TLSEnvironment
	if dbFlag {
		env, err = envs.Get(envName)
		if err != nil {
			return err
		}
	} else if apiFlag {
		env, err = osctrlAPI.GetEnvironment(envName)
		if err != nil {
			return err
		}
	}
	flags, err := envs.GenerateFlags(env, secret, cert, osqueryValues)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", flags)
	return nil
}

func secretEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	var env environments.TLSEnvironment
	if dbFlag {
		env, err = envs.Get(envName)
		if err != nil {
			return err
		}
	} else if apiFlag {
		env, err = osctrlAPI.GetEnvironment(envName)
		if err != nil {
			return err
		}
	}
	fmt.Printf("%s\n", env.Secret)
	return nil
}

func certificateEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	var env environments.TLSEnvironment
	if dbFlag {
		env, err = envs.Get(envName)
		if err != nil {
			return err
		}
	} else if apiFlag {
		env, err = osctrlAPI.GetEnvironment(envName)
		if err != nil {
			return err
		}
	}
	fmt.Printf("%s\n", env.Certificate)
	return nil
}

func addScheduledQuery(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	// Get query name
	queryName := cmd.String("query-name")
	if queryName == "" {
		fmt.Println("❌ query name is required")
		os.Exit(1)
	}
	// Get query
	query := cmd.String("query")
	if query == "" {
		fmt.Println("❌ query is required")
		os.Exit(1)
	}
	// Get interval
	interval := cmd.Int("interval")
	if interval == 0 {
		fmt.Println("❌ interval is required")
		os.Exit(1)
	}
	// Add new scheduled query
	qData := environments.ScheduleQuery{
		Query:    query,
		Interval: json.Number(strconv.Itoa(interval)),
		Platform: cmd.String("platform"),
		Version:  cmd.String("version"),
	}
	if err := envs.AddScheduleConfQuery(envName, queryName, qData); err != nil {
		return err
	}
	fmt.Printf("✅ query %s was created successfully\n", queryName)
	return nil
}

func removeScheduledQuery(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	// Get query name
	queryName := cmd.String("query-name")
	if queryName == "" {
		fmt.Println("❌ query name is required")
		os.Exit(1)
	}
	// Remove query
	if err := envs.RemoveScheduleConfQuery(envName, queryName); err != nil {
		return err
	}
	fmt.Printf("✅ query %s was removed successfully\n", queryName)
	return nil
}

func addOsqueryOption(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	// Get option
	option := cmd.String("option")
	if option == "" {
		fmt.Println("❌ option is required")
		os.Exit(1)
	}
	// Get option type
	optionType := cmd.String("type")
	if optionType == "" {
		fmt.Println("❌ option type is required")
		os.Exit(1)
	}
	// Get option value based on the type
	var optionValue interface{}
	switch cmd.String("type") {
	case optionTypeBool:
		optionValue = cmd.Bool("bool-value")
	case optionTypeInt:
		optionValue = cmd.Int("int-value")
	case optionTypeString:
		optionValue = cmd.String("string-value")
	default:
		fmt.Printf("❌ invalid type! It can be %s, %s or %s\n", optionTypeBool, optionTypeInt, optionTypeString)
		os.Exit(1)
	}
	// Add osquery option
	if err := envs.AddOptionsConf(envName, option, optionValue); err != nil {
		return err
	}
	fmt.Printf("✅ option %s was added successfully\n", option)
	return nil
}

func removeOsqueryOption(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	// Get option
	option := cmd.String("option")
	if option == "" {
		fmt.Println("❌ option is required")
		os.Exit(1)
	}
	// Remove osquery option
	if err := envs.RemoveOptionsConf(envName, option); err != nil {
		return err
	}
	fmt.Printf("✅ option %s was added successfully\n", option)
	return nil
}

func addNewPack(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	// Get pack name
	pName := cmd.String("pack")
	if pName == "" {
		fmt.Println("❌ pack name is required")
		os.Exit(1)
	}
	// Compose query pack
	pack := environments.PackEntry{
		Platform: cmd.String("platform"),
		Version:  cmd.String("version"),
		Shard:    json.Number(strconv.Itoa(cmd.Int("shard"))),
	}
	// Add pack to configuration
	if err := envs.AddQueryPackConf(envName, pName, pack); err != nil {
		return err
	}
	fmt.Printf("✅ pack %s was added successfully\n", pName)
	return nil
}

func removePack(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	// Get pack name
	pName := cmd.String("pack")
	if pName == "" {
		fmt.Println("❌ pack name is required")
		os.Exit(1)
	}
	// Remove pack from configuration
	if err := envs.RemoveQueryPackConf(envName, pName); err != nil {
		return err
	}
	fmt.Printf("✅ pack %s was added successfully\n", pName)
	return nil
}

func addLocalPack(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	// Get pack name
	pName := cmd.String("pack")
	if pName == "" {
		fmt.Println("❌ pack name is required")
		os.Exit(1)
	}
	// Get pack local path
	pPath := cmd.String("pack-path")
	if pPath == "" {
		fmt.Println("❌ pack path is required")
		os.Exit(1)
	}
	// Add pack to configuration option
	if err := envs.AddQueryPackConf(envName, pName, pPath); err != nil {
		return err
	}
	fmt.Printf("✅ pack %s was added successfully\n", pName)
	return nil
}

func addPackQuery(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	// Get query name
	packName := cmd.String("pack")
	if packName == "" {
		fmt.Println("❌ pack name is required")
		os.Exit(1)
	}
	// Get query
	query := cmd.String("query")
	if query == "" {
		fmt.Println("❌ query is required")
		os.Exit(1)
	}
	// Get query name
	queryName := cmd.String("query-name")
	if queryName == "" {
		fmt.Println("❌ query name is required")
		os.Exit(1)
	}
	// Get interval
	interval := cmd.Int("interval")
	if interval == 0 {
		fmt.Println("❌ interval is required")
		os.Exit(1)
	}
	// Add new scheduled query
	qData := environments.ScheduleQuery{
		Query:    query,
		Interval: json.Number(strconv.Itoa(interval)),
		Platform: cmd.String("platform"),
		Version:  cmd.String("version"),
	}
	if err := envs.AddQueryToPackConf(envName, packName, queryName, qData); err != nil {
		return err
	}
	fmt.Printf("✅ query %s was added to pack %s successfully\n", queryName, packName)
	return nil
}

func removePackQuery(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Println("❌ environment name is required")
		os.Exit(1)
	}
	// Get query name
	packName := cmd.String("pack")
	if packName == "" {
		fmt.Println("❌ pack name is required")
		os.Exit(1)
	}
	// Get query name
	queryName := cmd.String("query-name")
	if queryName == "" {
		fmt.Println("❌ query name is required")
		os.Exit(1)
	}
	// Remove query
	if err := envs.RemoveQueryFromPackConf(envName, packName, queryName); err != nil {
		return err
	}
	fmt.Printf("✅ query %s was removed from pack %s successfully\n", queryName, packName)
	return nil
}
