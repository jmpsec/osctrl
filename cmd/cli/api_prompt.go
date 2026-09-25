package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/jmpsec/osctrl/pkg/apiclient"
	"golang.org/x/term"
)

// missingAPIConfiguration reports whether the loaded API configuration is
// unusable: both URL and token must be present for any API command to work.
func missingAPIConfiguration(conf apiclient.JSONConfigurationAPI) bool {
	return conf.URL == "" || conf.Token == ""
}

// isTerminalStdin reports whether stdin is an interactive terminal. Prompts
// are only offered when this is true; non-interactive callers fail with the
// regular configuration errors instead of blocking on a prompt.
func isTerminalStdin() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// promptMissingAPIConfiguration asks for the API URL and token values that
// are still missing. Values already present (flags, environment, config
// file) are accepted as-is and not re-asked. The token is read without
// echoing. Returns an error in non-interactive contexts or when the user
// provides an empty value.
func promptMissingAPIConfiguration(conf *apiclient.JSONConfigurationAPI) error {
	if !missingAPIConfiguration(*conf) {
		return nil
	}
	if !isTerminalStdin() {
		if conf.URL == "" && conf.Token == "" {
			return fmt.Errorf("no API configuration found: use --api-file, --api-url/--api-token, API_URL/API_TOKEN, or run interactively to be prompted")
		}
		if conf.URL == "" {
			return fmt.Errorf("API URL is required: use --api-url, API_URL, or run interactively to be prompted")
		}
		return fmt.Errorf("API token is required: use --api-token, API_TOKEN, or run interactively to be prompted")
	}
	fmt.Println("No osctrl API configuration found. Please provide the connection details.")
	if conf.URL == "" {
		value, err := promptLine("API URL")
		if err != nil {
			return err
		}
		conf.URL = value
	}
	if conf.Token == "" {
		value, err := promptSecret("API token")
		if err != nil {
			return err
		}
		conf.Token = value
	}
	return nil
}

// promptLine reads a non-hidden value from the terminal.
func promptLine(label string) (string, error) {
	for {
		fmt.Printf(" -> %s: ", label)
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("error reading %s: %w", strings.ToLower(label), err)
		}
		value := strings.TrimSpace(line)
		if value != "" {
			return value, nil
		}
		fmt.Printf("❌ %s is required\n", label)
	}
}

// promptSecret reads a hidden value from the terminal, echoing a newline so
// the following output starts on a fresh line.
func promptSecret(label string) (string, error) {
	for {
		fmt.Printf(" -> %s: ", label)
		value, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if err != nil {
			return "", fmt.Errorf("error reading %s: %w", strings.ToLower(label), err)
		}
		secret := strings.TrimSpace(string(value))
		if secret != "" {
			return secret, nil
		}
		fmt.Printf("❌ %s is required\n", label)
	}
}
