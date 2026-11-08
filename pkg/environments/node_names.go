package environments

import (
	"errors"
	"fmt"

	"gorm.io/gorm"
)

// Nodes and posture rows reference their environment by NAME. Raw table names
// because pkg/nodes and pkg/posture import this package; absent only in
// package tests.
const (
	nodesTable   = "osquery_nodes"
	postureTable = "node_posture"
	// Query/carve targets of type "environment" store the env as submitted
	// (name or UUID); result reads resolve them, so names must follow renames.
	queryTargetsTable = "distributed_query_targets"
)

var (
	// ErrEnvHasNodes: deleting an environment that still has nodes would
	// orphan them under a name anyone could recreate.
	ErrEnvHasNodes = errors.New("environment still has enrolled nodes")
	// ErrNameHasNodes: nodes (orphaned by an earlier delete or rename) still
	// carry this name, so a new environment with it would inherit them.
	ErrNameHasNodes = errors.New("nodes still carry this environment name")
)

// countNodesNamed counts live nodes whose environment column equals name.
func countNodesNamed(tx *gorm.DB, name string) (int64, error) {
	if !tx.Migrator().HasTable(nodesTable) {
		return 0, nil
	}
	var n int64
	if err := tx.Table(nodesTable).Where("environment = ? AND deleted_at IS NULL", name).Count(&n).Error; err != nil {
		return 0, fmt.Errorf("count nodes %w", err)
	}
	return n, nil
}

// UpdateFields applies patch to env in one transaction. A "name" change also
// moves every name-keyed row (nodes, posture) to the new name, so a rename
// never leaves nodes behind under the old name.
func (environment *EnvManager) UpdateFields(env TLSEnvironment, patch map[string]interface{}) error {
	return environment.DB.Transaction(func(tx *gorm.DB) error {
		// Captured before Updates, which writes the patch back into env.
		oldName := env.Name
		newName, renaming := patch["name"].(string)
		if renaming && newName != oldName {
			n, err := countNodesNamed(tx, newName)
			if err != nil {
				return err
			}
			if n > 0 {
				return ErrNameHasNodes
			}
		}
		if err := tx.Model(&env).Updates(patch).Error; err != nil {
			return err
		}
		if !renaming || newName == oldName {
			return nil
		}
		for _, table := range []string{nodesTable, postureTable} {
			if !tx.Migrator().HasTable(table) {
				continue
			}
			if err := tx.Table(table).Where("environment = ?", oldName).Update("environment", newName).Error; err != nil {
				return fmt.Errorf("rename %s %w", table, err)
			}
		}
		if tx.Migrator().HasTable(queryTargetsTable) {
			if err := tx.Table(queryTargetsTable).Where("type = ? AND value = ?", "environment", oldName).Update("value", newName).Error; err != nil {
				return fmt.Errorf("rename %s %w", queryTargetsTable, err)
			}
		}
		return nil
	})
}
