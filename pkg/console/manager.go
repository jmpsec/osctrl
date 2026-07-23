package console

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"github.com/jmpsec/osctrl/pkg/types"
	"gorm.io/gorm"
)

const defaultCommandTimeout = 10 * time.Second

type Manager struct {
	DB      *gorm.DB
	Queries *queries.Queries
}

func NewManager(db *gorm.DB, queryManager *queries.Queries) *Manager {
	if err := db.AutoMigrate(&Session{}, &Command{}); err != nil {
		panic(fmt.Sprintf("failed to migrate console tables: %v", err))
	}
	return &Manager{DB: db, Queries: queryManager}
}

func (m *Manager) CreateSession(env environments.TLSEnvironment, node nodes.OsqueryNode, creator string) (Session, error) {
	session := Session{
		EnvironmentID: env.ID,
		NodeID:        node.ID,
		NodeUUID:      node.UUID,
		Creator:       creator,
		CWD:           DefaultCWD(node.Platform),
		Platform:      node.Platform,
		Active:        true,
	}
	if err := m.DB.Create(&session).Error; err != nil {
		return Session{}, err
	}
	return session, nil
}

func (m *Manager) GetSession(sessionID uint) (Session, error) {
	var session Session
	if err := m.DB.First(&session, sessionID).Error; err != nil {
		return Session{}, err
	}
	return session, nil
}

func (m *Manager) TouchSession(sessionID uint) (Session, error) {
	if err := m.DB.Model(&Session{}).
		Where("id = ? AND active = ?", sessionID, true).
		UpdateColumn("updated_at", time.Now()).Error; err != nil {
		return Session{}, err
	}
	return m.GetSession(sessionID)
}

func (m *Manager) SubmitCommand(sessionID uint, input string, osqueryModeOpt ...bool) (Command, ParsedCommand, error) {
	return m.SubmitCommandWithTimeout(sessionID, input, defaultCommandTimeout, osqueryModeOpt...)
}

func (m *Manager) SubmitCommandWithTimeout(sessionID uint, input string, timeout time.Duration, osqueryModeOpt ...bool) (Command, ParsedCommand, error) {
	if timeout <= 0 {
		timeout = defaultCommandTimeout
	}
	var session Session
	if err := m.DB.First(&session, sessionID).Error; err != nil {
		return Command{}, ParsedCommand{}, err
	}
	if !session.Active {
		return Command{}, ParsedCommand{}, fmt.Errorf("console session is closed")
	}
	var pending int64
	if err := m.DB.Model(&Command{}).
		Where("session_id = ? AND status IN ?", sessionID, []string{StatusQueued, StatusDelivered}).
		Count(&pending).Error; err != nil {
		return Command{}, ParsedCommand{}, err
	}
	if pending > 0 {
		return Command{}, ParsedCommand{}, fmt.Errorf("another command is still pending")
	}

	osqueryMode := false
	if len(osqueryModeOpt) > 0 {
		osqueryMode = osqueryModeOpt[0]
	}
	parsed, err := ParseInput(input, session.CWD, session.Platform, osqueryMode)
	if err != nil {
		return Command{}, ParsedCommand{}, err
	}

	command := Command{
		SessionID:     sessionID,
		Input:         input,
		TranslatedSQL: parsed.SQL,
		Status:        StatusCompleted,
	}
	if parsed.Kind == CommandRemote {
		command.Status = StatusQueued
	}

	err = m.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&command).Error; err != nil {
			return err
		}
		if parsed.Kind == CommandLocal {
			return nil
		}

		extra, err := json.Marshal(map[string]uint{"session_id": session.ID, "command_id": command.ID})
		if err != nil {
			return err
		}
		distributed := queries.DistributedQuery{
			Name:          queries.GenQueryName(),
			Query:         parsed.SQL,
			Creator:       session.Creator,
			Active:        true,
			Hidden:        true,
			Type:          queries.ConsoleQueryType,
			EnvironmentID: session.EnvironmentID,
			Expiration:    time.Now().Add(timeout),
			Expected:      1,
			ExtraData:     string(extra),
		}
		if err := tx.Create(&distributed).Error; err != nil {
			return err
		}
		nodeQuery := queries.NodeQuery{
			NodeID:  session.NodeID,
			QueryID: distributed.ID,
			Status:  queries.DistributedQueryStatusPending,
		}
		if err := tx.Create(&nodeQuery).Error; err != nil {
			return err
		}
		command.DistributedQueryName = distributed.Name
		return tx.Model(&command).Update("distributed_query_name", distributed.Name).Error
	})
	if err != nil {
		return Command{}, ParsedCommand{}, err
	}

	return command, parsed, nil
}

func (m *Manager) CloseSession(sessionID uint) error {
	now := time.Now()
	return m.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Session{}).Where("id = ?", sessionID).
			Updates(map[string]any{"active": false, "closed_at": &now}).Error; err != nil {
			return err
		}
		return tx.Model(&Command{}).
			Where("session_id = ? AND status IN ?", sessionID, []string{StatusQueued, StatusDelivered}).
			Updates(map[string]any{"status": StatusExpired, "expired_at": &now}).Error
	})
}

func (m *Manager) GetCommand(sessionID, commandID uint) (Command, error) {
	var command Command
	if err := m.DB.Where("session_id = ?", sessionID).First(&command, commandID).Error; err != nil {
		return Command{}, err
	}
	return command, nil
}

func (m *Manager) RefreshCommandStatus(commandID uint) (Command, error) {
	var command Command
	if err := m.DB.First(&command, commandID).Error; err != nil {
		return Command{}, err
	}
	if command.DistributedQueryName == "" || isTerminalStatus(command.Status) {
		return command, nil
	}

	var distributed queries.DistributedQuery
	if err := m.DB.Where("name = ?", command.DistributedQueryName).First(&distributed).Error; err != nil {
		return Command{}, err
	}
	var nodeQuery queries.NodeQuery
	if err := m.DB.Where("query_id = ?", distributed.ID).First(&nodeQuery).Error; err != nil {
		return Command{}, err
	}

	now := time.Now()
	updates := map[string]any{}
	switch nodeQuery.Status {
	case queries.DistributedQueryStatusPending:
		if distributed.Expiration.Before(now) {
			updates["status"] = StatusExpired
			updates["expired_at"] = &now
			if err := m.expireDistributedQuery(distributed.ID); err != nil {
				return Command{}, err
			}
		}
	case queries.DistributedQueryStatusCompleted:
		status, errText, err := m.completedStatusForCommand(command)
		if err != nil {
			return Command{}, err
		}
		updates["status"] = status
		updates["completed_at"] = &now
		if errText != "" {
			updates["error"] = errText
		}
	case queries.DistributedQueryStatusError:
		updates["status"] = StatusError
		updates["error"] = "osquery returned an error for this command"
		updates["completed_at"] = &now
	case queries.DistributedQueryStatusExpired:
		updates["status"] = StatusExpired
		updates["expired_at"] = &now
	}
	if len(updates) > 0 {
		if err := m.DB.Model(&command).Updates(updates).Error; err != nil {
			return Command{}, err
		}
		if err := m.DB.First(&command, commandID).Error; err != nil {
			return Command{}, err
		}
	}
	return command, nil
}

func (m *Manager) expireDistributedQuery(queryID uint) error {
	return m.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&queries.DistributedQuery{}).
			Where("id = ?", queryID).
			Updates(map[string]any{"expired": true, "active": false}).Error; err != nil {
			return err
		}
		return tx.Model(&queries.NodeQuery{}).
			Where("query_id = ? AND status = ?", queryID, queries.DistributedQueryStatusPending).
			Update("status", queries.DistributedQueryStatusExpired).Error
	})
}

func (m *Manager) CommandResults(commandID uint) ([]map[string]any, error) {
	command, err := m.RefreshCommandStatus(commandID)
	if err != nil {
		return nil, err
	}
	return m.queryResults(command.DistributedQueryName)
}

func (m *Manager) History(envID, nodeID uint, creator string, limit int) ([]HistoryEntry, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}
	var commands []Command
	err := m.DB.Model(&Command{}).
		Joins("JOIN console_sessions ON console_sessions.id = console_commands.session_id").
		Where("console_sessions.environment_id = ? AND console_sessions.node_id = ? AND console_sessions.creator = ?", envID, nodeID, creator).
		Order("console_commands.created_at DESC").
		Limit(limit).
		Find(&commands).Error
	if err != nil {
		return nil, err
	}

	history := make([]HistoryEntry, 0, len(commands))
	for i := len(commands) - 1; i >= 0; i-- {
		command := commands[i]
		results, err := m.queryResults(command.DistributedQueryName)
		if err != nil {
			results = []map[string]any{}
		}
		history = append(history, HistoryEntry{Command: command, Results: results})
	}
	return history, nil
}

func (m *Manager) completedStatusForCommand(command Command) (string, string, error) {
	if !isCDCommand(command.Input) {
		return StatusCompleted, "", nil
	}

	var session Session
	if err := m.DB.First(&session, command.SessionID).Error; err != nil {
		return StatusError, "", err
	}
	parsed, err := Parse(command.Input, session.CWD, session.Platform)
	if err != nil {
		return StatusError, err.Error(), nil
	}
	if parsed.Command != "cd" {
		return StatusCompleted, "", nil
	}

	rows, err := m.queryResults(command.DistributedQueryName)
	if err != nil {
		return StatusError, "", err
	}
	if len(rows) == 0 {
		return StatusError, fmt.Sprintf("directory not found: %s", parsed.Path), nil
	}
	if err := m.DB.Model(&session).Update("cwd", parsed.Path).Error; err != nil {
		return StatusError, "", err
	}
	return StatusCompleted, "", nil
}

func isCDCommand(input string) bool {
	fields := strings.Fields(input)
	return len(fields) > 0 && strings.EqualFold(fields[0], "cd")
}

func (m *Manager) queryResults(queryName string) ([]map[string]any, error) {
	rows := []map[string]any{}
	if queryName == "" {
		return rows, nil
	}
	err := logging.StreamQueryResults(m.DB, queryName, func(row logging.OsqueryQueryData) error {
		decoded, err := decodeResultRows([]byte(row.Data))
		if err != nil {
			return err
		}
		rows = append(rows, decoded...)
		return nil
	})
	return rows, err
}

func decodeResultRows(data []byte) ([]map[string]any, error) {
	var wrapped types.QueryWriteData
	if err := json.Unmarshal(data, &wrapped); err == nil && wrapped.Result != nil {
		data = wrapped.Result
	}

	var rows []map[string]any
	if err := json.Unmarshal(data, &rows); err != nil {
		return nil, err
	}
	return rows, nil
}

func isTerminalStatus(status string) bool {
	switch status {
	case StatusCompleted, StatusError, StatusExpired:
		return true
	default:
		return false
	}
}
