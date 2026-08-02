package fileexplorer

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/filequery"
	"github.com/jmpsec/osctrl/pkg/logging"
	"github.com/jmpsec/osctrl/pkg/nodes"
	"github.com/jmpsec/osctrl/pkg/queries"
	"gorm.io/gorm"
)

const (
	defaultRequestTimeout = 10 * time.Second
	maxPendingRequests    = 8
)

type Manager struct {
	DB      *gorm.DB
	Queries *queries.Queries
}

func NewManager(db *gorm.DB, queryManager *queries.Queries) *Manager {
	if err := db.AutoMigrate(&Session{}, &Request{}); err != nil {
		panic(fmt.Sprintf("failed to migrate file explorer tables: %v", err))
	}
	return &Manager{DB: db, Queries: queryManager}
}

func (m *Manager) CreateSession(env environments.TLSEnvironment, node nodes.OsqueryNode, creator string) (Session, error) {
	session := Session{
		EnvironmentID: env.ID,
		NodeID:        node.ID,
		NodeUUID:      node.UUID,
		Creator:       creator,
		Platform:      node.Platform,
		Root:          filequery.DefaultRoot(node.Platform),
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

func (m *Manager) CloseSession(sessionID uint) error {
	now := time.Now()
	return m.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&Session{}).Where("id = ?", sessionID).
			Updates(map[string]any{"active": false, "closed_at": &now}).Error; err != nil {
			return err
		}
		return tx.Model(&Request{}).
			Where("session_id = ? AND status = ?", sessionID, StatusQueued).
			Updates(map[string]any{"status": StatusExpired, "expired_at": &now}).Error
	})
}

func (m *Manager) ListDirectory(sessionID uint, target string, timeout time.Duration) (Request, error) {
	return m.submitRequest(sessionID, ActionList, target, timeout)
}

func (m *Manager) StatPath(sessionID uint, target string, timeout time.Duration) (Request, error) {
	return m.submitRequest(sessionID, ActionStat, target, timeout)
}

func (m *Manager) submitRequest(sessionID uint, action, target string, timeout time.Duration) (Request, error) {
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}

	var session Session
	if err := m.DB.First(&session, sessionID).Error; err != nil {
		return Request{}, err
	}
	if !session.Active {
		return Request{}, fmt.Errorf("file explorer session is closed")
	}

	var pending int64
	if err := m.DB.Model(&Request{}).
		Where("session_id = ? AND status = ?", sessionID, StatusQueued).
		Count(&pending).Error; err != nil {
		return Request{}, err
	}
	if pending >= maxPendingRequests {
		return Request{}, fmt.Errorf("too many file explorer requests are still pending")
	}

	resolved := filequery.ResolvePath(target, session.Root, session.Platform)
	sql, err := requestSQL(action, resolved)
	if err != nil {
		return Request{}, err
	}

	request := Request{
		SessionID:     session.ID,
		Action:        action,
		Path:          resolved,
		TranslatedSQL: sql,
		Status:        StatusQueued,
	}

	err = m.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&request).Error; err != nil {
			return err
		}

		extra, err := json.Marshal(map[string]uint{"session_id": session.ID, "request_id": request.ID})
		if err != nil {
			return err
		}
		distributed := queries.DistributedQuery{
			Name:          queries.GenQueryName(),
			Query:         sql,
			Creator:       session.Creator,
			Active:        true,
			Hidden:        true,
			Type:          queries.FileExplorerQueryType,
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
		request.DistributedQueryName = distributed.Name
		return tx.Model(&request).Update("distributed_query_name", distributed.Name).Error
	})
	if err != nil {
		return Request{}, err
	}
	return request, nil
}

func requestSQL(action, target string) (string, error) {
	switch action {
	case ActionList:
		return filequery.ListDirectorySQL(target), nil
	case ActionStat:
		return filequery.StatPathSQL(target), nil
	default:
		return "", fmt.Errorf("unsupported file explorer action %q", action)
	}
}

func (m *Manager) GetRequest(sessionID, requestID uint) (Request, error) {
	var request Request
	if err := m.DB.Where("session_id = ?", sessionID).First(&request, requestID).Error; err != nil {
		return Request{}, err
	}
	return request, nil
}

func (m *Manager) RefreshRequestStatus(requestID uint) (Request, error) {
	var request Request
	if err := m.DB.First(&request, requestID).Error; err != nil {
		return Request{}, err
	}
	if request.DistributedQueryName == "" || isTerminalStatus(request.Status) {
		return request, nil
	}

	var distributed queries.DistributedQuery
	if err := m.DB.Where("name = ?", request.DistributedQueryName).First(&distributed).Error; err != nil {
		return Request{}, err
	}
	var nodeQuery queries.NodeQuery
	if err := m.DB.Where("query_id = ?", distributed.ID).First(&nodeQuery).Error; err != nil {
		return Request{}, err
	}

	now := time.Now()
	updates := map[string]any{}
	switch nodeQuery.Status {
	case queries.DistributedQueryStatusPending:
		if distributed.Expiration.Before(now) {
			updates["status"] = StatusExpired
			updates["expired_at"] = &now
			if err := m.expireDistributedQuery(distributed.ID); err != nil {
				return Request{}, err
			}
		}
	case queries.DistributedQueryStatusCompleted:
		updates["status"] = StatusCompleted
		updates["completed_at"] = &now
	case queries.DistributedQueryStatusError:
		updates["status"] = StatusError
		updates["error"] = "osquery returned an error for this file explorer request"
		updates["completed_at"] = &now
	case queries.DistributedQueryStatusExpired:
		updates["status"] = StatusExpired
		updates["expired_at"] = &now
	}
	if len(updates) > 0 {
		if err := m.DB.Model(&request).Updates(updates).Error; err != nil {
			return Request{}, err
		}
		if err := m.DB.First(&request, requestID).Error; err != nil {
			return Request{}, err
		}
	}
	return request, nil
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

func (m *Manager) RequestResults(requestID uint) ([]Entry, error) {
	request, err := m.RefreshRequestStatus(requestID)
	if err != nil {
		return nil, err
	}
	entries := []Entry{}
	if request.DistributedQueryName == "" {
		return entries, nil
	}
	err = logging.StreamQueryResults(m.DB, request.DistributedQueryName, func(row logging.OsqueryQueryData) error {
		decoded, err := decodeEntries([]byte(row.Data))
		if err != nil {
			return err
		}
		entries = append(entries, decoded...)
		return nil
	})
	return entries, err
}

func isTerminalStatus(status string) bool {
	return status == StatusCompleted || status == StatusError || status == StatusExpired
}
