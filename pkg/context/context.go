package context

import (
	"fmt"
	"time"

	"github.com/jinzhu/gorm"
)

const (
	// DefaultEnrollPath as default value for enrolling nodes
	DefaultEnrollPath string = "enroll"
	// DefaultLogPath as default value for logging data from nodes
	DefaultLogPath string = "log"
	// DefaultLogInterval as default interval for logging data from nodes
	DefaultLogInterval int = 10
	// DefaultConfigPath as default value for configuring nodes
	DefaultConfigPath string = "config"
	// DefaultConfigInterval as default interval for configuring nodes
	DefaultConfigInterval int = 10
	// DefaultQueryReadPath as default value for distributing on-demand queries to nodes
	DefaultQueryReadPath string = "read"
	// DefaultQueryWritePath as default value for collecting results from on-demand queries
	DefaultQueryWritePath string = "write"
	// DefaultQueryInterval as default interval for distributing on-demand queries to nodes
	DefaultQueryInterval int = 10
	// DefaultCarverInitPath as default init endpoint for the carver
	DefaultCarverInitPath string = "init"
	// DefaultCarverBlockPath as default block endpoint for the carver
	DefaultCarverBlockPath string = "block"
	// DefaultContextIcon as default icon to use for contexts
	DefaultContextIcon string = "fas fa-wrench"
	// DefaultContextType as default type of context
	DefaultContextType string = "osquery"
	// DefaultSecretLength as default length for secrets
	DefaultSecretLength int = 64
	// DefaultLinkExpire as default time in hours to expire enroll/remove links
	DefaultLinkExpire int = 24
)

// TLSContext to hold each of the TLS context
type TLSContext struct {
	gorm.Model
	Name             string `gorm:"index"`
	Hostname         string
	Secret           string
	EnrollSecretPath string
	EnrollExpire     time.Time
	RemoveSecretPath string
	RemoveExpire     time.Time
	Type             string
	DebugHTTP        bool
	Icon             string
	Configuration    string
	Certificate      string
	ConfigInterval   int
	LogInterval      int
	QueryInterval    int
	EnrollPath       string
	LogPath          string
	ConfigPath       string
	QueryReadPath    string
	QueryWritePath   string
	CarverInitPath   string
	CarverBlockPath  string
}

// MapContext to hold the TLS contexts by name
type MapContext map[string]TLSContext

// Context keeps all TLS Contexts
type Context struct {
	DB *gorm.DB
}

// CreateContexts to initialize the context struct
func CreateContexts(backend *gorm.DB) *Context {
	var c *Context
	c = &Context{DB: backend}
	return c
}

// Get TLSContext by name
func (context *Context) Get(name string) (TLSContext, error) {
	var ctx TLSContext
	if err := context.DB.Where("name = ?", name).First(&ctx).Error; err != nil {
		return ctx, err
	}
	return ctx, nil
}

// Empty generates an empty TLSContext with default values
func (context *Context) Empty(name, hostname string) TLSContext {
	return TLSContext{
		Name:             name,
		Hostname:         hostname,
		Secret:           generateRandomString(DefaultSecretLength),
		EnrollSecretPath: generateKSUID(),
		RemoveSecretPath: generateKSUID(),
		EnrollExpire:     time.Now(),
		RemoveExpire:     time.Now(),
		Type:             DefaultContextType,
		DebugHTTP:        false,
		Icon:             DefaultContextIcon,
		Configuration:    "",
		Certificate:      "",
		ConfigInterval:   DefaultConfigInterval,
		LogInterval:      DefaultLogInterval,
		QueryInterval:    DefaultQueryInterval,
		EnrollPath:       DefaultEnrollPath,
		LogPath:          DefaultLogPath,
		ConfigPath:       DefaultConfigPath,
		QueryReadPath:    DefaultQueryReadPath,
		QueryWritePath:   DefaultQueryWritePath,
		CarverInitPath:   DefaultCarverInitPath,
		CarverBlockPath:  DefaultCarverBlockPath,
	}
}

// Create new TLSContext
func (context *Context) Create(ctx TLSContext) error {
	if context.DB.NewRecord(ctx) {
		if err := context.DB.Create(&ctx).Error; err != nil {
			return fmt.Errorf("Create TLSContext %v", err)
		}
	} else {
		return fmt.Errorf("db.NewRecord did not return true")
	}
	return nil
}

// Exists checks if TLSContext exists already
func (context *Context) Exists(name string) bool {
	var results int
	context.DB.Model(&TLSContext{}).Where("name = ?", name).Count(&results)
	return (results > 0)
}

// All gets all TLSContext
func (context *Context) All() ([]TLSContext, error) {
	var ctxs []TLSContext
	if err := context.DB.Find(&ctxs).Error; err != nil {
		return ctxs, err
	}
	return ctxs, nil
}

// GetMap returns the map of contexts by name
func (context *Context) GetMap() (MapContext, error) {
	all, err := context.All()
	if err != nil {
		return MapContext{}, fmt.Errorf("error getting contexts %v", err)
	}
	_map := make(MapContext)
	for _, c := range all {
		_map[c.Name] = c
	}
	return _map, nil
}

// Delete TLSContext by name
func (context *Context) Delete(name string) error {
	ctx, err := context.Get(name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	if err := context.DB.Delete(&ctx).Error; err != nil {
		return fmt.Errorf("Delete %v", err)
	}
	return nil
}

// Update TLSContext
func (context *Context) Update(c TLSContext) error {
	ctx, err := context.Get(c.Name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	if err := context.DB.Model(&ctx).Updates(c).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// UpdateConfiguration to update configuration for a context
func (context *Context) UpdateConfiguration(name, configuration string) error {
	ctx, err := context.Get(name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	if err := context.DB.Model(&ctx).Update("configuration", configuration).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// UpdateIntervals to update intervals for a context
func (context *Context) UpdateIntervals(name string, csecs, lsecs, qsecs int) error {
	ctx, err := context.Get(name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	updated := ctx
	updated.ConfigInterval = csecs
	updated.LogInterval = lsecs
	updated.QueryInterval = qsecs
	if err := context.DB.Model(&ctx).Updates(updated).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// RotateSecrets to replace Secret and SecretPath for a context
func (context *Context) RotateSecrets(name string) error {
	ctx, err := context.Get(name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	rotated := ctx
	rotated.Secret = generateRandomString(DefaultSecretLength)
	rotated.EnrollSecretPath = generateKSUID()
	rotated.RemoveSecretPath = generateKSUID()
	rotated.EnrollExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	rotated.RemoveExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := context.DB.Model(&ctx).Updates(rotated).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// RotateEnrollPath to replace SecretPath for enrolling in a context
func (context *Context) RotateEnrollPath(name string) error {
	ctx, err := context.Get(name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	rotated := ctx
	rotated.EnrollSecretPath = generateKSUID()
	rotated.EnrollExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := context.DB.Model(&ctx).Updates(rotated).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// RotateSecret to replace the current Secret for a context
func (context *Context) RotateSecret(name string) error {
	ctx, err := context.Get(name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	rotated := ctx
	rotated.Secret = generateRandomString(DefaultSecretLength)
	rotated.EnrollExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := context.DB.Model(&ctx).Updates(rotated).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// ExpireEnroll to expire the enroll in a context
func (context *Context) ExpireEnroll(name string) error {
	ctx, err := context.Get(name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	if err := context.DB.Model(&ctx).Update("enroll_expire", time.Now()).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// RotateRemove to replace Secret and SecrtPath for enrolling in a context
func (context *Context) RotateRemove(name string) error {
	ctx, err := context.Get(name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	rotated := ctx
	rotated.RemoveSecretPath = generateKSUID()
	rotated.RemoveExpire = time.Now().Add(time.Duration(DefaultLinkExpire) * time.Hour)
	if err := context.DB.Model(&ctx).Updates(rotated).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}

// ExpireRemove to expire the remove in a context
func (context *Context) ExpireRemove(name string) error {
	ctx, err := context.Get(name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	if err := context.DB.Model(&ctx).Update("remove_expire", time.Now()).Error; err != nil {
		return fmt.Errorf("Update %v", err)
	}
	return nil
}

// DebugHTTP to check if the context has enabled debugging for HTTP
func (context *Context) DebugHTTP(name string) bool {
	ctx, err := context.Get(name)
	if err != nil {
		return false
	}
	//return ((ctx.DebugHTTP || true) == false)
	return ctx.DebugHTTP
}

// ChangeDebugHTTP to change the value of DebugHTTP for a context
func (context *Context) ChangeDebugHTTP(name string, value bool) error {
	ctx, err := context.Get(name)
	if err != nil {
		return fmt.Errorf("error getting context %v", err)
	}
	if err := context.DB.Model(&ctx).Updates(map[string]interface{}{"debug_http": value}).Error; err != nil {
		return fmt.Errorf("Updates %v", err)
	}
	return nil
}
