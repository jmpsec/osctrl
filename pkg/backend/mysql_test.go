package backend

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gorm.io/driver/mysql"
	"gorm.io/gorm/schema"
)

type mysqlTypes struct {
	Unique    string `gorm:"uniqueIndex"`
	Composite string `gorm:"uniqueIndex:idx_c"`
	Sized     string `gorm:"uniqueIndex;size:32"`
	Indexed   string `gorm:"index"`
	Plain     string
	Number    uint `gorm:"uniqueIndex:idx_c"`
}

func TestMySQLDialectorStringTypes(t *testing.T) {
	s, err := schema.Parse(&mysqlTypes{}, &sync.Map{}, schema.NamingStrategy{})
	require.NoError(t, err)
	d := mysqlDialector{&mysql.Dialector{Config: &mysql.Config{}}}
	for name, want := range map[string]string{
		"Unique":    "varchar(191)",
		"Composite": "varchar(191)",
		"Sized":     "varchar(32)",
		"Indexed":   "varchar(191)",
		"Plain":     "longtext",
		"Number":    "bigint unsigned",
	} {
		require.Equal(t, want, d.DataTypeOf(s.LookUpField(name)), name)
	}
}
