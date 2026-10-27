package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/config"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/posture"
	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/types"
	"github.com/jmpsec/osctrl/pkg/utils"
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
		return fmt.Errorf("environment name is required")
	}
	// Get environment hostname
	envHost := cmd.String("hostname")
	if envHost == "" {
		return fmt.Errorf("environment hostname is required")
	}
	// Get certificate
	var certificate string
	certFile := cmd.String("certificate")
	if certFile != "" {
		certificate = environments.ReadExternalFile(certFile)
	}
	// Get osquery values to generate flags
	osqueryValues := config.YAMLConfigurationOsquery{
		Config: cmd.Bool("config"),
		Logger: cmd.Bool("logger"),
		Query:  cmd.Bool("query"),
		Carve:  cmd.Bool("carve"),
	}
	if dbFlag {
		// Get matches name OR uuid: a UUID-shaped name could shadow another environment
		if utils.CheckUUID(envName) {
			return fmt.Errorf("environment name %s must not be a UUID", envName)
		}
		if envs.Exists(envName) {
			return fmt.Errorf("environment %s already exists", envName)
		}
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
		// Audit log
		auditlogsmgr.EnvAction(getShellUsername(), "add environment "+envName, "CLI", 0)
	} else if apiFlag {
		stored, err := addEnvironmentAPI(envName, envHost, certificate, cmd.Bool("debug"), osqueryValues)
		if err != nil {
			return err
		}
		envName = stored // the API lowercases the name
	}
	fmt.Printf("✅ environment %s was created successfully\n", envName)
	return nil
}

// addEnvironmentAPI creates the environment, then applies the follow-ups DB
// mode does, flags last. A failed follow-up leaves the environment in place
// and the error names the step.
// It returns the stored name.
func addEnvironmentAPI(name, host, certificate string, debug bool, osq config.YAMLConfigurationOsquery) (string, error) {
	created, err := osctrlAPI.CreateEnvironment(types.EnvCreateRequest{
		Name:     name,
		Hostname: host,
		Type:     environments.DefaultEnvironmentType,
		Icon:     environments.DefaultEnvironmentIcon,
	})
	if err != nil {
		return "", err
	}
	id := created.UUID
	step := func(what string, err error) error {
		if err == nil {
			return nil
		}
		return fmt.Errorf("environment %s was created, but %s failed (finish or delete it): %w", created.Name, what, err)
	}
	// Default configuration parts and decorators, as DB mode stores them
	cnf, err := pureEnvs.GenStructConf([]byte(pureEnvs.GenEmptyConfiguration(true)))
	if err != nil {
		return created.Name, step("default configuration", err)
	}
	for _, part := range []struct {
		section string
		value   interface{}
	}{
		{environments.SectionOptions, cnf.Options},
		{environments.SectionSchedule, cnf.Schedule},
		{environments.SectionPacks, cnf.Packs},
		{environments.SectionDecorators, cnf.Decorators},
		{environments.SectionATC, cnf.ATC},
	} {
		value, err := pureEnvs.GenSerializedConf(part.value, true)
		if err == nil {
			err = osctrlAPI.PatchEnvConfig(id, part.section, value)
		}
		if err != nil {
			return created.Name, step("default configuration ("+part.section+")", err)
		}
	}
	if _, err := osctrlAPI.ExtendEnrollment(id); err != nil {
		return created.Name, step("enroll link extension", err)
	}
	if _, err := osctrlAPI.ExtendRemove(id); err != nil {
		return created.Name, step("remove link extension", err)
	}
	if certificate != "" {
		if err := osctrlAPI.UploadCertificate(id, certificate); err != nil {
			return created.Name, step("certificate upload", err)
		}
	}
	if debug {
		if err := osctrlAPI.PatchEnvironment(id, types.EnvUpdateRequest{DebugHTTP: &debug}); err != nil {
			return created.Name, step("debug", err)
		}
	}
	return created.Name, step("flags update", patchGeneratedFlagsAPI(id, osq))
}

// pureEnvs runs the environments manager methods that do not use the
// database (configuration and flag generation) in API mode.
var pureEnvs = &environments.EnvManager{}

// patchGeneratedFlagsAPI regenerates the flags of env from what the API
// returns for it and stores them. The token must be an environment admin.
func patchGeneratedFlagsAPI(env string, osq config.YAMLConfigurationOsquery) error {
	e, err := osctrlAPI.GetEnvironment(env)
	if err != nil {
		return err
	}
	flags, err := pureEnvs.GenerateFlags(e, "", "", osq)
	if err != nil {
		return err
	}
	return osctrlAPI.PatchEnvConfig(env, "flags", flags)
}

func updateEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		return fmt.Errorf("environment name is required")
	}
	// Get osquery values to generate flags
	osqueryValues := config.YAMLConfigurationOsquery{
		Config: cmd.Bool("config-plugin"),
		Logger: cmd.Bool("logger-plugin"),
		Query:  cmd.Bool("query-plugin"),
		Carve:  cmd.Bool("carve-plugin"),
	}
	// --debug and --enroll change only when given
	var debug, enroll *bool
	if cmd.IsSet("debug") {
		v := cmd.Bool("debug")
		debug = &v
	}
	if cmd.IsSet("enroll") {
		v := cmd.Bool("enroll")
		enroll = &v
	}
	hostname := cmd.String("hostname")
	// Package URLs by enroll action, in a fixed order
	packages := [][2]string{
		{settings.SetDebPackage, cmd.String("deb")},
		{settings.SetRpmPackage, cmd.String("rpm")},
		{settings.SetMsiPackage, cmd.String("msi")},
		{settings.SetMacPackage, cmd.String("pkg")},
	}
	// Intervals, 0 is unchanged
	configInterval, logInterval, queryInterval := cmd.Int("config"), cmd.Int("logging"), cmd.Int("query")
	// Flags are regenerated only when something they encode is given: a
	// plugin flag, the hostname or an interval. --debug, --enroll and package
	// URLs leave stored (possibly hand-edited) flags alone.
	regenFlags := cmd.IsSet("config-plugin") || cmd.IsSet("logger-plugin") || cmd.IsSet("query-plugin") || cmd.IsSet("carve-plugin") ||
		hostname != "" || configInterval != 0 || logInterval != 0 || queryInterval != 0
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		if hostname != "" {
			env.Hostname = hostname
		}
		pkgFields := map[string]*string{
			settings.SetDebPackage: &env.DebPackage,
			settings.SetRpmPackage: &env.RpmPackage,
			settings.SetMsiPackage: &env.MsiPackage,
			settings.SetMacPackage: &env.PkgPackage,
		}
		for _, p := range packages {
			if p[1] != "" {
				*pkgFields[p[0]] = p[1]
			}
		}
		if logInterval != 0 {
			env.LogInterval = logInterval
		}
		if configInterval != 0 {
			env.ConfigInterval = configInterval
		}
		if queryInterval != 0 {
			env.QueryInterval = queryInterval
		}
		// Update environment
		if err := envs.Update(env); err != nil {
			return err
		}
		if err := envs.UpdateBooleans(env.UUID, debug, enroll); err != nil {
			return err
		}
		if regenFlags {
			flags, err := envs.GenerateFlagsEnv(env.UUID, "", "", osqueryValues)
			if err != nil {
				return err
			}
			if err := envs.UpdateFlags(env.UUID, flags); err != nil {
				return err
			}
		}
		// Audit log
		auditlogsmgr.EnvAction(getShellUsername(), "update environment "+envName, "CLI", env.ID)
	} else if apiFlag {
		// The API rejects intervals below 1: fail before applying anything
		for _, v := range []int{configInterval, logInterval, queryInterval} {
			if v < 0 {
				return fmt.Errorf("intervals must be greater than zero, got %d", v)
			}
		}
		if hostname != "" || debug != nil || enroll != nil {
			req := types.EnvUpdateRequest{DebugHTTP: debug, AcceptEnrolls: enroll}
			if hostname != "" {
				req.Hostname = &hostname
			}
			if err := osctrlAPI.PatchEnvironment(envName, req); err != nil {
				return fmt.Errorf("updating environment: %w", err)
			}
		}
		nonZero := func(v int) *int {
			if v == 0 {
				return nil
			}
			return &v
		}
		if configInterval != 0 || logInterval != 0 || queryInterval != 0 {
			if err := osctrlAPI.PatchEnvironmentIntervals(envName, nonZero(configInterval), nonZero(logInterval), nonZero(queryInterval)); err != nil {
				return fmt.Errorf("updating intervals: %w", err)
			}
		}
		for _, p := range packages {
			if p[1] != "" {
				if err := osctrlAPI.SetEnrollPackageURL(envName, p[0], p[1]); err != nil {
					return fmt.Errorf("updating package (%s): %w", p[0], err)
				}
			}
		}
		if regenFlags {
			if err := patchGeneratedFlagsAPI(envName, osqueryValues); err != nil {
				return fmt.Errorf("updating flags: %w", err)
			}
		}
	}
	fmt.Printf("✅ environment %s was updated successfully\n", envName)
	return nil
}

// confirmEnvDelete asks for the environment name on in and returns an error
// unless the line read is exactly name.
func confirmEnvDelete(name string, in io.Reader, out io.Writer) error {
	fmt.Fprint(out, "Type the environment name to confirm deletion: ")
	line, err := bufio.NewReader(in).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("deletion of environment %s not confirmed: %w", name, err)
	}
	if strings.TrimRight(line, "\r\n") != name {
		return fmt.Errorf("deletion of environment %s not confirmed", name)
	}
	return nil
}

func deleteEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		return fmt.Errorf("environment name is required")
	}
	if !cmd.Bool("yes") && !silentFlag {
		if err := confirmEnvDelete(envName, os.Stdin, os.Stdout); err != nil {
			return err
		}
	}
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		if err := envs.Delete(env.UUID); err != nil {
			return err
		}
		// Audit log
		auditlogsmgr.EnvAction(getShellUsername(), "delete environment "+env.Name, "CLI", env.ID)
	} else if apiFlag {
		if err := osctrlAPI.DeleteEnvironment(envName); err != nil {
			return err
		}
	}
	fmt.Printf("✅ environment %s was deleted successfully\n", envName)
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
		return fmt.Errorf("environment name is required")
	}
	// Get osquery values to generate flags
	osqueryValues := config.YAMLConfigurationOsquery{
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
		if env, err := envs.Get(envName); err == nil { // same line the API writes for a config PATCH
			auditlogsmgr.ConfAction(getShellUsername(), "config patch on env "+env.Name, "CLI", env.ID)
		}
	} else if apiFlag {
		if err := patchGeneratedFlagsAPI(envName, osqueryValues); err != nil {
			return err
		}
	}
	fmt.Printf("✅ flags for environment %s were regenerated\n", envName)
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
		if err := table.Bulk(data); err != nil {
			return fmt.Errorf("error bulk table - %w", err)
		}
		if err := table.Render(); err != nil {
			return fmt.Errorf("error rendering table - %w", err)
		}
	} else {
		fmt.Printf("No environments\n")
	}
	return nil
}

func quickAddEnvironment(ctx context.Context, cmd *cli.Command) error {
	// Get environment name
	envName := cmd.String("name")
	if envName == "" {
		fmt.Fprintln(os.Stderr, "❌ environment name is required")
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
		fmt.Fprintf(os.Stderr, "❌ invalid target! It can be %s or %s\n", targetShell, targetPowershell)
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
		auditlogsmgr.EnvAction(getShellUsername(), "extend enrollment for environment "+env.Name, "CLI", env.ID)
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
		return fmt.Errorf("environment name is required")
	}
	msg := "enrollment rotated successfully"
	if dbFlag {
		env, err := envs.Get(envName)
		if err != nil {
			return err
		}
		if err := envs.RotateEnroll(env.UUID); err != nil {
			return err
		}
		auditlogsmgr.EnvAction(getShellUsername(), "rotate enrollment for environment "+env.Name, "CLI", env.ID)
	} else if apiFlag {
		msg, err = osctrlAPI.RotateEnrollment(envName)
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
		auditlogsmgr.EnvAction(getShellUsername(), "expire enrollment for environment "+env.Name, "CLI", env.ID)
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
		auditlogsmgr.EnvAction(getShellUsername(), "notexpire enrollment for environment "+env.Name, "CLI", env.ID)
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
		auditlogsmgr.EnvAction(getShellUsername(), "extend removal for environment "+env.Name, "CLI", env.ID)
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
		return fmt.Errorf("environment name is required")
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
		auditlogsmgr.EnvAction(getShellUsername(), "rotate removal for environment "+env.Name, "CLI", env.ID)
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
		auditlogsmgr.EnvAction(getShellUsername(), "expire removal for environment "+env.Name, "CLI", env.ID)
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
		auditlogsmgr.EnvAction(getShellUsername(), "notexpire removal for environment "+env.Name, "CLI", env.ID)
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
	osqueryValues := config.YAMLConfigurationOsquery{
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

// scheduleQueryFromFlags is the scheduled or pack query given with --query,
// --interval, --platform and --version.
func scheduleQueryFromFlags(cmd *cli.Command) (environments.ScheduleQuery, error) {
	query := cmd.String("query")
	if query == "" {
		return environments.ScheduleQuery{}, fmt.Errorf("query is required")
	}
	interval := cmd.Int("interval")
	if interval == 0 {
		return environments.ScheduleQuery{}, fmt.Errorf("interval is required")
	}
	return environments.ScheduleQuery{
		Query:    query,
		Interval: json.Number(strconv.Itoa(interval)),
		Platform: cmd.String("platform"),
		Version:  cmd.String("version"),
	}, nil
}

func addScheduledQuery(ctx context.Context, cmd *cli.Command) error {
	envName := cmd.String("name")
	if envName == "" {
		return fmt.Errorf("environment name is required")
	}
	queryName := cmd.String("query-name")
	if queryName == "" {
		return fmt.Errorf("query name is required")
	}
	qData, err := scheduleQueryFromFlags(cmd)
	if err != nil {
		return err
	}
	if err := editEnvConfigSection(envName, environments.SectionSchedule, func(c string) (string, error) {
		return environments.AddScheduleQueries(c, environments.ScheduleConf{queryName: qData})
	}); err != nil {
		return err
	}
	fmt.Printf("✅ query %s was created successfully\n", queryName)
	return nil
}

func addPostureQueries(ctx context.Context, cmd *cli.Command) error {
	envName := cmd.String("name")
	if envName == "" {
		return fmt.Errorf("environment name is required")
	}
	profileID := cmd.String("profile")
	if profileID == "" {
		return fmt.Errorf("posture profile is required")
	}
	prefix := cmd.String("prefix")
	if prefix == "" {
		return fmt.Errorf("posture query prefix is required")
	}
	interval := cmd.Int("interval")
	if interval < 0 {
		return fmt.Errorf("posture query interval must be zero or greater")
	}
	schedule, err := postureProfileScheduleQueries(profileID, prefix, interval)
	if err != nil {
		return err
	}
	if err := editEnvConfigSection(envName, environments.SectionSchedule, func(c string) (string, error) {
		return environments.AddScheduleQueries(c, schedule)
	}); err != nil {
		return err
	}
	fmt.Printf("✅ posture profile %s added %d scheduled queries to %s\n", profileID, len(schedule), envName)
	return nil
}

func postureProfileScheduleQueries(profileID, prefix string, intervalOverride int) (environments.ScheduleConf, error) {
	profile := posture.GetProfile(profileID)
	if profile == nil {
		return nil, fmt.Errorf("unknown posture profile %q", profileID)
	}
	schedule := make(environments.ScheduleConf, len(profile.Queries))
	for name, query := range profile.Queries {
		interval := query.Interval
		if intervalOverride > 0 {
			interval = intervalOverride
		}
		queryName := query.QueryName
		if queryName == "" {
			queryName = prefix + name
		}
		schedule[queryName] = environments.ScheduleQuery{
			Query:    query.Query,
			Interval: json.Number(strconv.Itoa(interval)),
			Platform: query.Platform,
			Snapshot: query.Snapshot,
		}
	}
	return schedule, nil
}

func removeScheduledQuery(ctx context.Context, cmd *cli.Command) error {
	envName := cmd.String("name")
	if envName == "" {
		return fmt.Errorf("environment name is required")
	}
	queryName := cmd.String("query-name")
	if queryName == "" {
		return fmt.Errorf("query name is required")
	}
	if err := editEnvConfigSection(envName, environments.SectionSchedule, func(c string) (string, error) {
		return environments.RemoveScheduleQuery(c, queryName)
	}); err != nil {
		return err
	}
	fmt.Printf("✅ query %s was removed successfully\n", queryName)
	return nil
}

func addOsqueryOption(ctx context.Context, cmd *cli.Command) error {
	envName := cmd.String("name")
	if envName == "" {
		return fmt.Errorf("environment name is required")
	}
	option := cmd.String("option")
	if option == "" {
		return fmt.Errorf("option is required")
	}
	// Get option value based on the type
	var optionValue interface{}
	switch cmd.String("type") {
	case "":
		return fmt.Errorf("option type is required")
	case optionTypeBool:
		optionValue = cmd.Bool("bool-value")
	case optionTypeInt:
		optionValue = cmd.Int("int-value")
	case optionTypeString:
		optionValue = cmd.String("string-value")
	default:
		return fmt.Errorf("invalid type! It can be %s, %s or %s", optionTypeBool, optionTypeInt, optionTypeString)
	}
	if err := editEnvConfigSection(envName, environments.SectionOptions, func(c string) (string, error) {
		return environments.SetOption(c, option, optionValue)
	}); err != nil {
		return err
	}
	fmt.Printf("✅ option %s was added successfully\n", option)
	return nil
}

func removeOsqueryOption(ctx context.Context, cmd *cli.Command) error {
	envName := cmd.String("name")
	if envName == "" {
		return fmt.Errorf("environment name is required")
	}
	option := cmd.String("option")
	if option == "" {
		return fmt.Errorf("option is required")
	}
	if err := editEnvConfigSection(envName, environments.SectionOptions, func(c string) (string, error) {
		return environments.RemoveOption(c, option)
	}); err != nil {
		return err
	}
	fmt.Printf("✅ option %s was removed successfully\n", option)
	return nil
}

func addNewPack(ctx context.Context, cmd *cli.Command) error {
	envName := cmd.String("name")
	if envName == "" {
		return fmt.Errorf("environment name is required")
	}
	pName := cmd.String("pack")
	if pName == "" {
		return fmt.Errorf("pack name is required")
	}
	pack := environments.PackEntry{
		Platform: cmd.String("platform"),
		Version:  cmd.String("version"),
		Shard:    json.Number(strconv.Itoa(cmd.Int("shard"))),
	}
	if err := editEnvConfigSection(envName, environments.SectionPacks, func(c string) (string, error) {
		return environments.SetPack(c, pName, pack)
	}); err != nil {
		return err
	}
	fmt.Printf("✅ pack %s was added successfully\n", pName)
	return nil
}

func removePack(ctx context.Context, cmd *cli.Command) error {
	envName := cmd.String("name")
	if envName == "" {
		return fmt.Errorf("environment name is required")
	}
	pName := cmd.String("pack")
	if pName == "" {
		return fmt.Errorf("pack name is required")
	}
	if err := editEnvConfigSection(envName, environments.SectionPacks, func(c string) (string, error) {
		return environments.RemovePack(c, pName)
	}); err != nil {
		return err
	}
	fmt.Printf("✅ pack %s was removed successfully\n", pName)
	return nil
}

func addLocalPack(ctx context.Context, cmd *cli.Command) error {
	envName := cmd.String("name")
	if envName == "" {
		return fmt.Errorf("environment name is required")
	}
	pName := cmd.String("pack")
	if pName == "" {
		return fmt.Errorf("pack name is required")
	}
	pPath := cmd.String("pack-path")
	if pPath == "" {
		return fmt.Errorf("pack path is required")
	}
	if err := editEnvConfigSection(envName, environments.SectionPacks, func(c string) (string, error) {
		return environments.SetPack(c, pName, pPath)
	}); err != nil {
		return err
	}
	fmt.Printf("✅ pack %s was added successfully\n", pName)
	return nil
}

func addPackQuery(ctx context.Context, cmd *cli.Command) error {
	envName := cmd.String("name")
	if envName == "" {
		return fmt.Errorf("environment name is required")
	}
	packName := cmd.String("pack")
	if packName == "" {
		return fmt.Errorf("pack name is required")
	}
	queryName := cmd.String("query-name")
	if queryName == "" {
		return fmt.Errorf("query name is required")
	}
	qData, err := scheduleQueryFromFlags(cmd)
	if err != nil {
		return err
	}
	if err := editEnvConfigSection(envName, environments.SectionPacks, func(c string) (string, error) {
		return environments.AddQueryToPack(c, packName, queryName, qData)
	}); err != nil {
		return err
	}
	fmt.Printf("✅ query %s was added to pack %s successfully\n", queryName, packName)
	return nil
}

func removePackQuery(ctx context.Context, cmd *cli.Command) error {
	envName := cmd.String("name")
	if envName == "" {
		return fmt.Errorf("environment name is required")
	}
	packName := cmd.String("pack")
	if packName == "" {
		return fmt.Errorf("pack name is required")
	}
	queryName := cmd.String("query-name")
	if queryName == "" {
		return fmt.Errorf("query name is required")
	}
	if err := editEnvConfigSection(envName, environments.SectionPacks, func(c string) (string, error) {
		return environments.RemoveQueryFromPack(c, packName, queryName)
	}); err != nil {
		return err
	}
	fmt.Printf("✅ query %s was removed from pack %s successfully\n", queryName, packName)
	return nil
}
