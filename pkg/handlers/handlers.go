package handlers

import (
	"fmt"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/jmpsec/osctrl/pkg/utils"
)

type ProcessingQuery struct {
	Envs          []string
	Platforms     []string
	UUIDs         []string
	Hosts         []string
	Tags          []string
	EnvID         uint
	InactiveHours int64
}

type Managers struct {
	Envs  *environments.EnvManager
	Nodes *nodes.NodeManager
	Tags  *tags.TagManager
}

// CreateQueryCarve - Create On-demand Query or Carve, to be used in osctrl-admin or osctrl-api
func CreateQueryCarve(data ProcessingQuery, manager Managers, newQuery queries.DistributedQuery) ([]uint, error) {
	var expected []uint
	targetNodesID := []uint{}
	// Environments target
	if len(data.Envs) > 0 {
		expected = []uint{}
		for _, e := range data.Envs {
			// TODO: Check if user has permissions to query the environment
			if (e != "") && manager.Envs.Exists(e) {
				nodes, err := manager.Nodes.GetByEnv(e, nodes.ActiveNodes, data.InactiveHours)
				if err != nil {
					return targetNodesID, fmt.Errorf("error getting nodes by environment: %w", err)
				}
				for _, n := range nodes {
					expected = append(expected, n.ID)
				}
			}
		}
		targetNodesID = utils.Intersect(targetNodesID, expected)
	}
	// Platforms target
	if len(data.Platforms) > 0 {
		expected = []uint{}
		platforms, _ := manager.Nodes.GetEnvIDPlatforms(data.EnvID)
		for _, p := range data.Platforms {
			if (p != "") && utils.Contains(platforms, p) {
				nodes, err := manager.Nodes.GetByPlatform(data.EnvID, p, nodes.ActiveNodes, data.InactiveHours)
				if err != nil {
					return targetNodesID, fmt.Errorf("error getting nodes by platform: %w", err)
				}
				for _, n := range nodes {
					expected = append(expected, n.ID)
				}
			}
		}
		targetNodesID = utils.Intersect(targetNodesID, expected)
	}
	// UUIDs target
	if len(data.UUIDs) > 0 {
		expected = []uint{}
		for _, u := range data.UUIDs {
			if u != "" {
				node, err := manager.Nodes.GetByUUIDEnv(u, data.EnvID)
				if err != nil {
					return targetNodesID, fmt.Errorf("error getting node %s and failed to create node query for it: %w", u, err)
				}
				expected = append(expected, node.ID)
			}
		}
		targetNodesID = utils.Intersect(targetNodesID, expected)
	}
	// Hostnames target
	if len(data.Hosts) > 0 {
		expected = []uint{}
		for _, _h := range data.Hosts {
			if _h != "" {
				node, err := manager.Nodes.GetByIdentifierEnv(_h, data.EnvID)
				if err != nil {
					return targetNodesID, fmt.Errorf("error getting node %s and failed to create node query for it: %w", _h, err)
				}
				expected = append(expected, node.ID)
			}
		}
		targetNodesID = utils.Intersect(targetNodesID, expected)
	}
	// Tags target
	if len(data.Tags) > 0 {
		expected = []uint{}
		for _, _t := range data.Tags {
			if _t != "" {
				exist, tag := manager.Tags.ExistsGet(tags.GetStrTagName(_t), data.EnvID)
				if exist {
					tagged, err := manager.Tags.GetTaggedNodes(tag)
					if err != nil {
						return targetNodesID, fmt.Errorf("error getting tagged nodes for tag %s: %w", _t, err)
					}
					for _, tn := range tagged {
						expected = append(expected, tn.NodeID)
					}
				}
			}
		}
		targetNodesID = utils.Intersect(targetNodesID, expected)
	}
	return targetNodesID, nil
}
