package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"

	"github.com/jmpsec/osctrl/pkg/auditlog"
	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v2"
)

// Helper function to convert a slice of audit logs entries into the data expected for output
func auditlogsToData(als []auditlog.AuditLog, m environments.MapEnvByID, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	for _, a := range als {
		data = append(data, auditlogToData(a, m, nil)...)
	}
	return data
}

// Helper function to convert an audit log entry into the data expected for output
func auditlogToData(a auditlog.AuditLog, m environments.MapEnvByID, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	_t := []string{
		a.CreatedAt.String(),
		a.Service,
		a.Username,
		a.Line,
		auditlogsmgr.LogTypeToString(a.LogType),
		auditlogsmgr.SeverityToString(a.Severity),
		a.SourceIP,
		m[a.EnvironmentID].Name,
	}
	data = append(data, _t)
	return data
}

func helperAuditLogs(als []auditlog.AuditLog, m environments.MapEnvByID) error {
	header := []string{
		"Created",
		"Service",
		"Username",
		"Line",
		"LogType",
		"Severity",
		"SourceIP",
		"Environment",
	}
	// Prepare output
	switch formatFlag {
	case jsonFormat:
		jsonRaw, err := json.Marshal(als)
		if err != nil {
			return fmt.Errorf("error marshaling - %w", err)
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		data := auditlogsToData(als, m, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error writing csv - %w", err)
		}
	case prettyFormat:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		if len(als) > 0 {
			fmt.Printf("Existing audit logs (%d):\n", len(als))
			data := auditlogsToData(als, m, nil)
			table.Bulk(data)
		} else {
			fmt.Println("No audit logs")
		}
		table.Render()
	}
	return nil
}

func auditLogs(c *cli.Context) error {
	var als []auditlog.AuditLog
	var m environments.MapEnvByID
	if dbFlag {
		als, err = auditlogsmgr.GetAll()
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		m, err = envs.GetMapByID()
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
	} else if apiFlag {
		als, err = osctrlAPI.GetAuditLogs()
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
		m, err = osctrlAPI.GetEnvMap()
		if err != nil {
			return fmt.Errorf("❌ %w", err)
		}
	}
	if err := helperAuditLogs(als, m); err != nil {
		return fmt.Errorf("❌ %w", err)
	}
	return nil
}
