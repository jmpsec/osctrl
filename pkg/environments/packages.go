package environments

import (
	"errors"
	"fmt"
	"time"

	"github.com/jmpsec/osctrl/pkg/settings"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// Architecture constants for enrolling packages.
const (
	ArchAmd64     string = "amd64"
	ArchArm64     string = "arm64"
	ArchX86_64    string = "x86_64"
	ArchAarch64   string = "aarch64"
	ArchUniversal string = "universal"
)

// ValidArchitectures is the set of accepted architecture values.
var ValidArchitectures = map[string]bool{
	ArchAmd64:     true,
	ArchArm64:     true,
	ArchX86_64:    true,
	ArchAarch64:   true,
	ArchUniversal: true,
	"":            true, // empty = "any" / default, for backward compat
}

// EnvironmentPackage stores a single enrolling package for an environment.
// An environment can have multiple packages per type (deb, rpm, msi, pkg),
// each targeting a different architecture.
type EnvironmentPackage struct {
	ID            uint           `gorm:"primarykey" json:"id"`
	CreatedAt     time.Time      `json:"created_at"`
	UpdatedAt     time.Time      `json:"updated_at"`
	DeletedAt     gorm.DeletedAt `gorm:"index" json:"-"`
	EnvironmentID uint           `gorm:"index" json:"environment_id"`
	Type          string         `gorm:"index" json:"type"`
	Architecture  string         `json:"architecture"`
	URL           string         `json:"url"`
	IsDefault     bool           `json:"is_default"`
}

// GetPackages retrieves all packages for an environment.
func (environment *EnvManager) GetPackages(envID uint) ([]EnvironmentPackage, error) {
	var pkgs []EnvironmentPackage
	if err := environment.DB.Where("environment_id = ?", envID).
		Order("type, architecture").Find(&pkgs).Error; err != nil {
		return pkgs, err
	}
	return pkgs, nil
}

// GetPackagesByType retrieves all packages of a specific type for an environment.
func (environment *EnvManager) GetPackagesByType(envID uint, pkgType string) ([]EnvironmentPackage, error) {
	var pkgs []EnvironmentPackage
	if err := environment.DB.Where("environment_id = ? AND type = ?", envID, pkgType).
		Order("architecture").Find(&pkgs).Error; err != nil {
		return pkgs, err
	}
	return pkgs, nil
}

// GetPackage retrieves a specific package by type and architecture.
func (environment *EnvManager) GetPackage(envID uint, pkgType, arch string) (EnvironmentPackage, error) {
	var pkg EnvironmentPackage
	// Try exact match first.
	err := environment.DB.Where("environment_id = ? AND type = ? AND architecture = ?", envID, pkgType, arch).
		First(&pkg).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return pkg, err
	}
	if err == nil {
		return pkg, nil
	}
	// Fall back to the default package for this type.
	err = environment.DB.Where("environment_id = ? AND type = ? AND is_default = ?", envID, pkgType, true).
		First(&pkg).Error
	if err == nil {
		return pkg, nil
	}
	// Fall back to any package of this type (first by architecture order).
	err = environment.DB.Where("environment_id = ? AND type = ?", envID, pkgType).
		Order("architecture").First(&pkg).Error
	return pkg, err
}

// AddPackage adds a new enrolling package to an environment.
func (environment *EnvManager) AddPackage(envID uint, pkgType, arch, url string, isDefault bool) error {
	if !ValidArchitectures[arch] {
		return fmt.Errorf("invalid architecture %q", arch)
	}
	if err := ValidatePackageReference(url); err != nil {
		return fmt.Errorf("AddPackage %w", err)
	}
	pkg := EnvironmentPackage{
		EnvironmentID: envID,
		Type:          pkgType,
		Architecture:  arch,
		URL:           url,
		IsDefault:     isDefault,
	}
	if isDefault {
		// Unset default on other packages of the same type.
		if err := environment.DB.Model(&EnvironmentPackage{}).
			Where("environment_id = ? AND type = ?", envID, pkgType).
			Update("is_default", false).Error; err != nil {
			return fmt.Errorf("AddPackage clear default %w", err)
		}
	}
	if err := environment.DB.Create(&pkg).Error; err != nil {
		return fmt.Errorf("AddPackage create %w", err)
	}
	return nil
}

// RemovePackage removes a package by ID.
func (environment *EnvManager) RemovePackage(envID, pkgID uint) error {
	result := environment.DB.Where("environment_id = ? AND id = ?", envID, pkgID).
		Delete(&EnvironmentPackage{})
	if result.Error != nil {
		return fmt.Errorf("RemovePackage %w", result.Error)
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// SetDefaultPackage sets a package as the default for its type.
func (environment *EnvManager) SetDefaultPackage(envID, pkgID uint) error {
	// Find the package to get its type.
	var pkg EnvironmentPackage
	if err := environment.DB.Where("environment_id = ? AND id = ?", envID, pkgID).First(&pkg).Error; err != nil {
		return err
	}
	// Unset default on other packages of the same type.
	if err := environment.DB.Model(&EnvironmentPackage{}).
		Where("environment_id = ? AND type = ?", envID, pkg.Type).
		Update("is_default", false).Error; err != nil {
		return err
	}
	// Set the new default.
	return environment.DB.Model(&pkg).Update("is_default", true).Error
}

// UpdatePackageURL updates the URL of an existing package.
func (environment *EnvManager) UpdatePackageURL(envID, pkgID uint, url string) error {
	if err := ValidatePackageReference(url); err != nil {
		return fmt.Errorf("UpdatePackageURL %w", err)
	}
	result := environment.DB.Model(&EnvironmentPackage{}).
		Where("environment_id = ? AND id = ?", envID, pkgID).
		Update("url", url)
	if result.Error != nil {
		return result.Error
	}
	if result.RowsAffected == 0 {
		return gorm.ErrRecordNotFound
	}
	return nil
}

// MigrateLegacyPackages copies the single-package fields from TLSEnvironment
// into the new EnvironmentPackage table. Called once during AutoMigrate.
func (environment *EnvManager) MigrateLegacyPackages() error {
	var envs []TLSEnvironment
	if err := environment.DB.Find(&envs).Error; err != nil {
		return err
	}
	for _, env := range envs {
		legacy := []struct {
			Type string
			URL  string
		}{
			{settings.PackageDeb, env.DebPackage},
			{settings.PackageRpm, env.RpmPackage},
			{settings.PackageMsi, env.MsiPackage},
			{settings.PackagePkg, env.PkgPackage},
		}
		for _, p := range legacy {
			if p.URL == "" {
				continue
			}
			// Check if packages already exist for this env+type (idempotent).
			var count int64
			environment.DB.Model(&EnvironmentPackage{}).
				Where("environment_id = ? AND type = ?", env.ID, p.Type).
				Count(&count)
			if count > 0 {
				continue
			}
			pkg := EnvironmentPackage{
				EnvironmentID: env.ID,
				Type:          p.Type,
				Architecture:  "",
				URL:           p.URL,
				IsDefault:     true,
			}
			if err := environment.DB.Create(&pkg).Error; err != nil {
				log.Warn().Err(err).Uint("env_id", env.ID).Str("type", p.Type).
					Msg("legacy package migration: failed to create row")
			}
		}
	}
	return nil
}
