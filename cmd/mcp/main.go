// osctrl-mcp serves osctrl's read-only surface over the Model Context
// Protocol, so an MCP client (Claude Code, Claude Desktop, or any other)
// can inspect a fleet through osctrl-api.
//
// It speaks MCP over stdio and is meant to be launched by the client, not
// run as a daemon. It holds no state and opens no listening socket; every
// request becomes an authenticated call to osctrl-api, so the token's
// existing per-environment permissions are what bound the agent.
//
// Give it a service user scoped to what the agent should read. It never
// issues a write, but a token that can write is still a token the process
// holds in memory.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"

	"github.com/jmpsec/osctrl/pkg/apiclient"
	osctrlmcp "github.com/jmpsec/osctrl/pkg/mcp"
	"github.com/jmpsec/osctrl/pkg/version"
)

const (
	serviceName = "osctrl-mcp"
	serviceDesc = "MCP server for osctrl"
)

// Build-time metadata (overridden via -ldflags "-X main.buildVersion=... -X main.buildCommit=... -X main.buildDate=...")
var (
	buildVersion = version.OsctrlVersion
	buildCommit  = "unknown"
	buildDate    = "unknown"
)

var (
	apiURL      string
	apiToken    string
	apiConfFile string
	insecure    bool
	allowWrites bool
	logLevel    string
)

func main() {
	cmd := &cli.Command{
		Name:    serviceName,
		Usage:   serviceDesc,
		Version: buildVersion,
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:        "api-url",
				Usage:       "Base URL of osctrl-api, e.g. https://osctrl.example.com",
				Sources:     cli.EnvVars("OSCTRL_API_URL"),
				Destination: &apiURL,
			},
			&cli.StringFlag{
				Name:        "api-token",
				Usage:       "Bearer token for osctrl-api (prefer OSCTRL_API_TOKEN over the flag so it stays out of the process list)",
				Sources:     cli.EnvVars("OSCTRL_API_TOKEN"),
				Destination: &apiToken,
			},
			&cli.StringFlag{
				Name:        "config",
				Aliases:     []string{"c"},
				Usage:       "Path to an osctrl-api.json holding url + token, as written by `osctrl-cli login --write`",
				Sources:     cli.EnvVars("OSCTRL_API_FILE"),
				Destination: &apiConfFile,
			},
			&cli.BoolFlag{
				Name:        "insecure",
				Usage:       "Skip TLS verification when talking to osctrl-api (development only)",
				Sources:     cli.EnvVars("OSCTRL_INSECURE"),
				Destination: &insecure,
			},
			&cli.BoolFlag{
				Name:        "allow-writes",
				Usage:       "Expose the mutating tools (run_query, expire_query, complete_query, tag_node). Off by default; the token's own permissions still apply",
				Sources:     cli.EnvVars("OSCTRL_MCP_ALLOW_WRITES"),
				Destination: &allowWrites,
			},
			&cli.StringFlag{
				Name:        "log-level",
				Value:       "info",
				Usage:       "Log level: debug, info, warn, error",
				Sources:     cli.EnvVars("OSCTRL_LOG_LEVEL"),
				Destination: &logLevel,
			},
			// Same output as the other binaries. Printing to stdout is safe
			// here even though stdout is the MCP transport: this exits before
			// the transport is ever created.
			&cli.BoolFlag{
				Name:    "version",
				Aliases: []string{"v"},
				Usage:   "Print version information",
				Action: func(ctx context.Context, cmd *cli.Command, b bool) error {
					if b {
						fmt.Printf("%s version=%s commit=%s date=%s\n", serviceName, buildVersion, buildCommit, buildDate)
						os.Exit(0)
					}
					return nil
				},
			},
		},
		HideVersion: true,
		Action:      run,
	}
	if err := cmd.Run(context.Background(), os.Args); err != nil {
		// stderr, never stdout: stdout is the MCP transport and any stray
		// byte there corrupts the JSON-RPC stream.
		fmt.Fprintf(os.Stderr, "%s: %v\n", serviceName, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, _ *cli.Command) error {
	initLogger()

	cfg, err := resolveConfig()
	if err != nil {
		return err
	}
	client, err := apiclient.CreateAPI(cfg, insecure)
	if err != nil {
		return fmt.Errorf("error creating API client - %w", err)
	}
	// Fail fast on a bad URL or a dead/rejected token. Without this the
	// server starts happily and every tool call fails one at a time, which
	// reads to the user as "the tools are broken" rather than "the token is
	// wrong".
	if err := client.CheckAPI(); err != nil {
		return fmt.Errorf("error reaching osctrl-api at %s - %w", cfg.URL, err)
	}

	log.Info().Str("api", cfg.URL).Str("version", buildVersion).
		Str("commit", buildCommit).Str("date", buildDate).Bool("writes", allowWrites).
		Msgf("%s starting on stdio", serviceName)
	opts := []osctrlmcp.Option{}
	if allowWrites {
		opts = append(opts, osctrlmcp.WithWrites(client))
	}
	srv := osctrlmcp.NewServer(client, buildVersion, opts...)
	if err := srv.Run(ctx, &sdk.StdioTransport{}); err != nil {
		return fmt.Errorf("mcp server - %w", err)
	}
	return nil
}

// resolveConfig assembles the API configuration from the config file first,
// then lets explicit flags/env vars override it. That ordering lets an
// operator keep a checked-in config file and still point one MCP client at a
// different environment without editing it.
func resolveConfig() (apiclient.JSONConfigurationAPI, error) {
	var cfg apiclient.JSONConfigurationAPI
	if apiConfFile != "" {
		loaded, err := apiclient.LoadConfiguration(apiConfFile)
		if err != nil {
			return cfg, fmt.Errorf("error loading %s - %w", apiConfFile, err)
		}
		cfg = loaded
	}
	if apiURL != "" {
		cfg.URL = apiURL
	}
	if apiToken != "" {
		cfg.Token = apiToken
	}
	if cfg.URL == "" {
		return cfg, fmt.Errorf("no API URL: pass --api-url, set OSCTRL_API_URL, or point --config at an osctrl-api.json")
	}
	if cfg.Token == "" {
		return cfg, fmt.Errorf("no API token: set OSCTRL_API_TOKEN, or point --config at an osctrl-api.json")
	}
	return cfg, nil
}

// initLogger sends every log line to stderr. stdout belongs to the MCP
// transport — zerolog's default stdout writer would interleave log JSON with
// protocol frames and break the session.
func initLogger() {
	switch strings.ToLower(logLevel) {
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr}).With().Caller().Logger()
}
