package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/jmpsec/osctrl/pkg/extensions"
	"github.com/jmpsec/osctrl/pkg/nodeconfig"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/osqueryversions"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/olekukonko/tablewriter"
	"github.com/rs/zerolog/log"
	"github.com/urfave/cli/v3"
)

// deleteNodeOverride removes the config and flags overrides, the osctrld
// status and the extension assignments and statuses of a node just deleted by
// UUID. ArchiveDeleteByUUID matches the
// uppercased UUID, so that is the node row's key. A failure is logged, not
// returned: the node is already gone.
// ponytail: the CLI has no Redis, so osctrl-tls may keep a cached copy for up
// to the cache TTL; it only applies if the same UUID re-enrolls in that window.
func deleteNodeOverride(uuid string) {
	uuid = strings.ToUpper(uuid)
	m, err := nodeconfig.NewManager(nodesmgr.DB, nil)
	if err == nil {
		err = m.Delete(context.Background(), uuid)
	}
	if err != nil {
		log.Err(err).Msgf("error removing config override of deleted node %s", uuid)
	}
	f, err := nodeconfig.NewFlagsManager(nodesmgr.DB, nil)
	if err == nil {
		err = errors.Join(f.Delete(context.Background(), uuid), f.DeleteStatus(uuid))
	}
	if err != nil {
		log.Err(err).Msgf("error removing flags override of deleted node %s", uuid)
	}
	e, err := extensions.NewManager(nodesmgr.DB)
	if err == nil {
		err = e.DeleteNode(uuid)
	}
	if err != nil {
		log.Err(err).Msgf("error removing extensions of deleted node %s", uuid)
	}
	o, err := osqueryversions.NewManager(nodesmgr.DB)
	if err == nil {
		err = o.DeleteNodeRecords(uuid)
	}
	if err != nil {
		log.Err(err).Msgf("error removing osquery pin of deleted node %s", uuid)
	}
}

// Helper function to convert a slice of nodes into the data expected for output
func nodesToData(nds []nodes.OsqueryNode, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	for _, n := range nds {
		data = append(data, nodeToData(n, nil)...)
	}
	return data
}

// Helper function to convert a node into the data expected for output
func nodeToData(n nodes.OsqueryNode, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	_n := []string{
		n.Hostname,
		n.UUID,
		n.Platform,
		n.PlatformVersion,
		n.Environment,
		nodeLastSeen(n),
		n.IPAddress,
		n.OsqueryVersion,
	}
	data = append(data, _n)
	return data
}

func listNodes(ctx context.Context, cmd *cli.Command) error {
	// Get flag values for this command
	target := "active"
	if cmd.Bool("all") {
		target = "all"
	}
	if cmd.Bool("inactive") {
		target = "inactive"
	}
	env := cmd.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	// Retrieve data
	var nds []nodes.OsqueryNode
	if dbFlag {
		e, lookupErr := envs.Get(env)
		if lookupErr != nil {
			return fmt.Errorf("error getting environment - %w", lookupErr)
		}
		nds, err = nodesmgr.GetByEnv(e.Name, target, settingsmgr.InactiveHours(e.ID))
		if err != nil {
			return fmt.Errorf("error getting nodes - %w", err)
		}
	} else if apiFlag {
		nds, err = osctrlAPI.GetNodes(env, target)
		if err != nil {
			return fmt.Errorf("error getting nodes - %w", err)
		}
	}
	header := []string{
		"Hostname",
		"UUID",
		"Platform",
		"PlatformVersion",
		"Environment",
		"Last Seen",
		"IPAddress",
		"OsqueryVersion",
	}
	// Prepare output
	switch formatFlag {
	case jsonFormat:
		jsonRaw, err := json.Marshal(nds)
		if err != nil {
			return fmt.Errorf("error marshaling - %w", err)
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		data := nodesToData(nds, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error writing csv - %w", err)
		}
	case prettyFormat:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		if len(nds) > 0 {
			fmt.Printf("Existing %s nodes (%d):\n", target, len(nds))
			data := nodesToData(nds, nil)
			if err := table.Bulk(data); err != nil {
				return fmt.Errorf("error bulk table - %w", err)
			}
		} else {
			fmt.Printf("No %s nodes\n", target)
		}
		if err := table.Render(); err != nil {
			return fmt.Errorf("error rendering table - %w", err)
		}
	}
	return nil
}

func deleteNode(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	uuid := cmd.String("uuid")
	if uuid == "" {
		fmt.Println("❌ uuid is required")
		os.Exit(1)
	}
	env := cmd.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	if dbFlag {
		if err := nodesmgr.ArchiveDeleteByUUID(uuid); err != nil {
			return fmt.Errorf("error deleting - %w", err)
		}
		deleteNodeOverride(uuid)
		// Audit log
		auditlogsmgr.NodeAction(getShellUsername(), "delete node "+uuid, "CLI", 0)
	} else if apiFlag {
		if err := osctrlAPI.DeleteNode(env, uuid); err != nil {
			return fmt.Errorf("error deleting node - %w", err)
		}
	}
	if !silentFlag {
		fmt.Println("✅ node was deleted successfully")
	}
	return nil
}

func tagNode(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	uuid := cmd.String("uuid")
	if uuid == "" {
		fmt.Println("❌ uuid is required")
		os.Exit(1)
	}
	env := cmd.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	tag := cmd.String("tag-value")
	if tag == "" {
		fmt.Println("❌ tag is required")
		os.Exit(1)
	}
	tagType := cmd.String("tag-type")
	tagCustom := cmd.String("custom")
	var tagTypeInt uint
	switch tagType {
	case tags.TagTypeEnvStr:
		tagTypeInt = tags.TagTypeEnv
	case tags.TagTypePlatformStr:
		tagTypeInt = tags.TagTypePlatform
	case tags.TagTypeTagStr:
		tagTypeInt = tags.TagTypeTag
	default:
		tagTypeInt = tags.TagTypeCustom

	}
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("error env get - %w", err)
		}
		n, err := nodesmgr.GetByUUIDEnv(uuid, e.ID)
		if err != nil {
			return fmt.Errorf("error get uuid - %w", err)
		}
		if err := tagsmgr.TagNode(tag, n, appName, false, tagTypeInt, tagCustom); err != nil {
			return fmt.Errorf("error tagging - %w", err)
		}
		// Audit log
		auditlogsmgr.NodeAction(getShellUsername(), "tag node "+uuid+" with "+tag, "CLI", e.ID)
	} else if apiFlag {
		if err := osctrlAPI.TagNode(env, uuid, tag, tagTypeInt, tagCustom); err != nil {
			return fmt.Errorf("error tagging node - %w", err)
		}
	}
	if !silentFlag {
		fmt.Println("✅ node was tagged successfully")
	}
	return nil
}

func _showNode(node nodes.OsqueryNode) error {
	header := []string{
		"Hostname",
		"UUID",
		"Platform",
		"PlatformVersion",
		"Environment",
		"Last Seen",
		"IPAddress",
		"OsqueryVersion",
	}
	// Prepare output
	switch formatFlag {
	case jsonFormat:
		jsonRaw, err := json.Marshal(node)
		if err != nil {
			return fmt.Errorf("error marshaling - %w", err)
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		data := nodeToData(node, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error writing csv - %w", err)
		}
	case prettyFormat:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		data := nodeToData(node, nil)
		if err := table.Bulk(data); err != nil {
			return fmt.Errorf("error bulk table - %w", err)
		}
		if err := table.Render(); err != nil {
			return fmt.Errorf("error rendering table - %w", err)
		}
	}
	return nil
}

func showNode(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	uuid := cmd.String("uuid")
	if uuid == "" {
		fmt.Println("❌ UUID is required")
		os.Exit(1)
	}
	env := cmd.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	var node nodes.OsqueryNode
	if dbFlag {
		node, err = nodesmgr.GetByUUID(uuid)
		if err != nil {
			return fmt.Errorf("error getting node - %w", err)
		}
	} else if apiFlag {
		node, err = osctrlAPI.GetNode(env, uuid)
		if err != nil {
			return fmt.Errorf("error getting node - %w", err)
		}
	}
	return _showNode(node)
}

func lookupNode(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	identifier := cmd.String("identifier")
	if identifier == "" {
		fmt.Println("❌ identifier is required")
		os.Exit(1)
	}
	var node nodes.OsqueryNode
	if dbFlag {
		node, err = nodesmgr.GetByIdentifier(identifier)
		if err != nil {
			return fmt.Errorf("error getting node - %w", err)
		}
	} else if apiFlag {
		node, err = osctrlAPI.LookupNode(identifier)
		if err != nil {
			return fmt.Errorf("error getting node - %w", err)
		}
	}
	return _showNode(node)
}
