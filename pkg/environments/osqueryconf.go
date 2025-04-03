package environments

import (
	"encoding/json"
	"fmt"
	"strings"
)

// OsqueryConf to hold the structure for the configuration
// https://osquery.readthedocs.io/en/stable/deployment/configuration/#configuration-specification
type OsqueryConf struct {
	Options    OptionsConf   `json:"options"`
	Schedule   ScheduleConf  `json:"schedule"`
	Packs      PacksConf     `json:"packs"`
	Decorators DecoratorConf `json:"decorators"`
	ATC        ATCConf       `json:"auto_table_construction"`
}

// OptionsConf for each part of the configuration
type OptionsConf map[string]interface{}

// ScheduleConf to hold all the schedule
// https://osquery.readthedocs.io/en/stable/deployment/configuration/#schedule
type ScheduleConf map[string]ScheduleQuery

// ScheduleQuery to hold the scheduled queries in the configuration
// https://osquery.readthedocs.io/en/stable/deployment/configuration/#schedule
type ScheduleQuery struct {
	Query    string      `json:"query,omitempty"`
	Interval json.Number `json:"interval,omitempty"`
	Removed  bool        `json:"removed,omitempty"`
	Snapshot bool        `json:"snapshot,omitempty"`
	Platform string      `json:"platform,omitempty"`
	Version  string      `json:"version,omitempty"`
	Shard    json.Number `json:"shard,omitempty"`
	Denylist bool        `json:"denylist,omitempty"`
}

// PacksConf to hold all the packs in the configuration
// https://osquery.readthedocs.io/en/stable/deployment/configuration/#packs
type PacksConf map[string]interface{}

// PacksEntries to hold all the parsed non-local packs
type PacksEntries map[string]PackEntry

// PackEntry to hold the struct for a single pack
type PackEntry struct {
	Queries   map[string]ScheduleQuery `json:"queries,omitempty"`
	Platform  string                   `json:"platform,omitempty"`
	Shard     json.Number              `json:"shard,omitempty"`
	Version   string                   `json:"version,omitempty"`
	Discovery []string                 `json:"discovery,omitempty"`
}

// DecoratorConf to hold the osquery decorators
// https://osquery.readthedocs.io/en/stable/deployment/configuration/#decorator-queries
type DecoratorConf struct {
	Load     []string    `json:"load,omitempty"`
	Always   []string    `json:"always,omitempty"`
	Interval interface{} `json:"interval,omitempty"`
}

// ATCConf to hold all the auto table construction in the configuration
// https://osquery.readthedocs.io/en/stable/deployment/configuration/#automatic-table-construction
type ATCConf map[string]interface{}

// RefreshConfiguration to take all parts and put them together in the configuration
func (environment *EnvironmentManager) RefreshConfiguration(idEnv string) error {
	env, err := environment.Get(idEnv)
	if err != nil {
		return fmt.Errorf("error structuring environment %w", err)
	}
	_options, err := environment.GenStructOptions([]byte(env.Options))
	if err != nil {
		return fmt.Errorf("error structuring options %w", err)
	}
	_schedule, err := environment.GenStructSchedule([]byte(env.Schedule))
	if err != nil {
		return fmt.Errorf("error structuring schedule %w", err)
	}
	_packs, err := environment.GenStructPacks([]byte(env.Packs))
	if err != nil {
		return fmt.Errorf("error structuring packs %w", err)
	}
	_decorators, err := environment.GenStructDecorators([]byte(env.Decorators))
	if err != nil {
		return fmt.Errorf("error structuring decorators %w", err)
	}
	_ATC, err := environment.GenStructATC([]byte(env.ATC))
	if err != nil {
		return fmt.Errorf("error structuring ATC %w", err)
	}
	conf := OsqueryConf{
		Options:    _options,
		Schedule:   _schedule,
		Packs:      _packs,
		Decorators: _decorators,
		ATC:        _ATC,
	}
	indentedConf, err := environment.GenSerializedConf(conf, true)
	if err != nil {
		return fmt.Errorf("error serializing configuration %w", err)
	}
	if err := environment.DB.Model(&env).Update("configuration", indentedConf).Error; err != nil {
		return fmt.Errorf("Update configuration %w", err)
	}
	return nil
}

// UpdateConfiguration to update configuration for an environment
func (environment *EnvironmentManager) UpdateConfiguration(idEnv string, cnf OsqueryConf) error {
	indentedConf, err := environment.GenSerializedConf(cnf, true)
	if err != nil {
		return fmt.Errorf("error serializing configuration %w", err)
	}
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Update("configuration", indentedConf).Error; err != nil {
		return fmt.Errorf("Update configuration %w", err)
	}
	return nil
}

// UpdateConfigurationParts to update all the configuration parts for an environment
func (environment *EnvironmentManager) UpdateConfigurationParts(idEnv string, cnf OsqueryConf) error {
	indentedOptions, err := environment.GenSerializedConf(cnf.Options, true)
	if err != nil {
		return fmt.Errorf("error serializing options %w", err)
	}
	indentedSchedule, err := environment.GenSerializedConf(cnf.Schedule, true)
	if err != nil {
		return fmt.Errorf("error serializing schedule %w", err)
	}
	indentedPacks, err := environment.GenSerializedConf(cnf.Packs, true)
	if err != nil {
		return fmt.Errorf("error serializing packs %w", err)
	}
	indentedDecorators, err := environment.GenSerializedConf(cnf.Decorators, true)
	if err != nil {
		return fmt.Errorf("error serializing decorators %w", err)
	}
	indentedATC, err := environment.GenSerializedConf(cnf.ATC, true)
	if err != nil {
		return fmt.Errorf("error serializing ATC %w", err)
	}
	if err := environment.DB.Model(&TLSEnvironment{}).Where("name = ? OR uuid = ?", idEnv, idEnv).Updates(TLSEnvironment{
		Options:    indentedOptions,
		Schedule:   indentedSchedule,
		Packs:      indentedPacks,
		Decorators: indentedDecorators,
		ATC:        indentedATC}).Error; err != nil {
		return fmt.Errorf("Update parts %w", err)
	}
	return nil
}

// GenSerializedConf to generate a serialized osquery configuration from the structured data
func (environment *EnvironmentManager) GenSerializedConf(structured interface{}, indent bool) (string, error) {
	indentStr := ""
	if indent {
		indentStr = "  "
	}
	jsonConf, err := json.MarshalIndent(structured, "", indentStr)
	if err != nil {
		return "", err
	}
	return string(jsonConf), nil
}

// GenStructConf to generate the components from the osquery configuration
func (environment *EnvironmentManager) GenStructConf(configuration []byte) (OsqueryConf, error) {
	var data OsqueryConf
	if err := json.Unmarshal(configuration, &data); err != nil {
		return data, err
	}
	return data, nil
}

// GenStructOptions to generate options from the serialized string
func (environment *EnvironmentManager) GenStructOptions(configuration []byte) (OptionsConf, error) {
	var data OptionsConf
	if err := json.Unmarshal(configuration, &data); err != nil {
		return data, err
	}
	return data, nil
}

// GenStructSchedule to generate schedule from the serialized string
func (environment *EnvironmentManager) GenStructSchedule(configuration []byte) (ScheduleConf, error) {
	var data ScheduleConf
	if err := json.Unmarshal(configuration, &data); err != nil {
		return data, err
	}
	return data, nil
}

// NodeStructSchedule to generate schedule that applies to a platform from the serialized string
func (environment *EnvironmentManager) NodeStructSchedule(configuration []byte, platform string) (ScheduleConf, error) {
	schedule, err := environment.GenStructSchedule(configuration)
	if err != nil {
		return ScheduleConf{}, fmt.Errorf("GenStructSchedule %w", err)
	}
	for k, s := range schedule {
		if !IsPlatformQuery(strings.ToLower(s.Platform), strings.ToLower(platform)) {
			delete(schedule, k)
		}
	}
	return schedule, nil
}

// GenStructPacks to generate packs from the serialized string
func (environment *EnvironmentManager) GenStructPacks(configuration []byte) (PacksConf, error) {
	var data PacksConf
	if err := json.Unmarshal(configuration, &data); err != nil {
		return data, err
	}
	return data, nil
}

// NodePacksEntries to generate packs parsed struct that applies to a platform from the serialized string
func (environment *EnvironmentManager) NodePacksEntries(configuration []byte, platform string) (PacksEntries, error) {
	packs, err := environment.GenPacksEntries(configuration)
	if err != nil {
		return PacksEntries{}, fmt.Errorf("GenPacksEntries %w", err)
	}
	for k, p := range packs {
		if !IsPlatformQuery(strings.ToLower(p.Platform), platform) {
			delete(packs, k)
		}
	}
	return packs, nil
}

// GenPacksEntries to generate packs parsed struct from the serialized string
func (environment *EnvironmentManager) GenPacksEntries(configuration []byte) (PacksEntries, error) {
	packsConf, err := environment.GenStructPacks(configuration)
	if err != nil {
		return PacksEntries{}, fmt.Errorf("GenStructPacks %w", err)
	}
	packsEntries := make(PacksEntries)
	for k, p := range packsConf {
		switch v := p.(type) {
		case string:
			// This is a local pack, do nothing
		default:
			rawdata, err := json.Marshal(v)
			if err != nil {
				return PacksEntries{}, fmt.Errorf("Marshal %w", err)
			}
			var parsed PackEntry
			if err := json.Unmarshal(rawdata, &parsed); err != nil {
				return PacksEntries{}, fmt.Errorf("Unmarshal %w", err)
			}
			packsEntries[k] = parsed
		}
	}
	return packsEntries, nil
}

// GenStructDecorators to generate decorators from the serialized string
func (environment *EnvironmentManager) GenStructDecorators(configuration []byte) (DecoratorConf, error) {
	var data DecoratorConf
	if err := json.Unmarshal(configuration, &data); err != nil {
		return data, err
	}
	return data, nil
}

// GenStructATC to generate ATC from the serialized string
func (environment *EnvironmentManager) GenStructATC(configuration []byte) (ATCConf, error) {
	var data ATCConf
	if err := json.Unmarshal(configuration, &data); err != nil {
		return data, err
	}
	return data, nil
}

// GenEmptyConfiguration to generate a serialized string with an empty configuration
func (environment *EnvironmentManager) GenEmptyConfiguration(indent bool) string {
	cnf := OsqueryConf{
		Options:  OptionsConf{},
		Schedule: ScheduleConf{},
		Packs:    PacksConf{},
		Decorators: DecoratorConf{
			Always: []string{
				DecoratorUsers,
				DecoratorHostname,
				DecoratorLoggedInUser,
				DecoratorOsqueryVersionHash,
				DecoratorMD5Process,
			},
		},
		ATC: ATCConf{},
	}
	str, err := environment.GenSerializedConf(cnf, indent)
	if err != nil {
		return ""
	}
	return str
}

// AddOptionsConf to add an osquery option to the configuration
func (environment *EnvironmentManager) AddOptionsConf(name, option string, value interface{}) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	// Parse options into struct
	_options, err := environment.GenStructOptions([]byte(env.Options))
	if err != nil {
		return fmt.Errorf("error structuring options %w", err)
	}
	// Add new option
	_options[option] = value
	// Generate serialized indented options
	indentedOptions, err := environment.GenSerializedConf(_options, true)
	if err != nil {
		return fmt.Errorf("error serializing options %w", err)
	}
	// Update options in environment
	if err := environment.UpdateOptions(name, indentedOptions); err != nil {
		return fmt.Errorf("error updating options %w", err)
	}
	// Refresh all configuration
	if err := environment.RefreshConfiguration(name); err != nil {
		return fmt.Errorf("error refreshing configuration %w", err)
	}
	return nil
}

// RemoveOptionsConf to remove an osquery option from the configuration
func (environment *EnvironmentManager) RemoveOptionsConf(name, option string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	// Parse options into struct
	_options, err := environment.GenStructOptions([]byte(env.Options))
	if err != nil {
		return fmt.Errorf("error structuring options %w", err)
	}
	// Remove option
	delete(_options, option)
	// Generate serialized indented options
	indentedOptions, err := environment.GenSerializedConf(_options, true)
	if err != nil {
		return fmt.Errorf("error serializing options %w", err)
	}
	// Update options in environment
	if err := environment.UpdateOptions(name, indentedOptions); err != nil {
		return fmt.Errorf("error updating options %w", err)
	}
	// Refresh all configuration
	if err := environment.RefreshConfiguration(name); err != nil {
		return fmt.Errorf("error refreshing configuration %w", err)
	}
	return nil
}

// AddScheduleConfQuery to add a new query to the osquery schedule
func (environment *EnvironmentManager) AddScheduleConfQuery(name, qName string, query ScheduleQuery) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	// Parse schedule into struct
	_schedule, err := environment.GenStructSchedule([]byte(env.Schedule))
	if err != nil {
		return fmt.Errorf("error structuring schedule %w", err)
	}
	// Add new query
	_schedule[qName] = query
	// Generate serialized indented schedule
	indentedSchedule, err := environment.GenSerializedConf(_schedule, true)
	if err != nil {
		return fmt.Errorf("error serializing schedule %w", err)
	}
	// Update schedule in environment
	if err := environment.UpdateSchedule(name, indentedSchedule); err != nil {
		return fmt.Errorf("error updating schedule %w", err)
	}
	// Refresh all configuration
	if err := environment.RefreshConfiguration(name); err != nil {
		return fmt.Errorf("error refreshing configuration %w", err)
	}
	return nil
}

// RemoveScheduleConfQuery to remove a query from the osquery schedule
func (environment *EnvironmentManager) RemoveScheduleConfQuery(name, qName string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	// Parse schedule into struct
	_schedule, err := environment.GenStructSchedule([]byte(env.Schedule))
	if err != nil {
		return fmt.Errorf("error structuring schedule %w", err)
	}
	// Remove query
	delete(_schedule, qName)
	// Generate serialized indented schedule
	indentedSchedule, err := environment.GenSerializedConf(_schedule, true)
	if err != nil {
		return fmt.Errorf("error serializing schedule %w", err)
	}
	// Update schedule in environment
	if err := environment.UpdateSchedule(name, indentedSchedule); err != nil {
		return fmt.Errorf("error updating schedule %w", err)
	}
	// Refresh all configuration
	if err := environment.RefreshConfiguration(name); err != nil {
		return fmt.Errorf("error refreshing configuration %w", err)
	}
	return nil
}

// AddQueryPackConf to add a new query pack to the osquery configuration
func (environment *EnvironmentManager) AddQueryPackConf(name, pName string, pack interface{}) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	// Parse packs into struct
	_packs, err := environment.GenStructPacks([]byte(env.Packs))
	if err != nil {
		return fmt.Errorf("error structuring packs %w", err)
	}
	// Add new local pack
	_packs[pName] = pack
	// Generate serialized indented packs
	indentedPacks, err := environment.GenSerializedConf(_packs, true)
	if err != nil {
		return fmt.Errorf("error serializing packs %w", err)
	}
	// Update schedule in environment
	if err := environment.UpdatePacks(name, indentedPacks); err != nil {
		return fmt.Errorf("error updating packs %w", err)
	}
	// Refresh all configuration
	if err := environment.RefreshConfiguration(name); err != nil {
		return fmt.Errorf("error refreshing configuration %w", err)
	}
	return nil
}

// RemoveQueryPackConf to add a new query pack to the osquery configuration
func (environment *EnvironmentManager) RemoveQueryPackConf(name, pName string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	// Parse packs into struct
	_packs, err := environment.GenStructPacks([]byte(env.Packs))
	if err != nil {
		return fmt.Errorf("error structuring packs %w", err)
	}
	// Remove pack
	delete(_packs, pName)
	// Generate serialized indented packs
	indentedPacks, err := environment.GenSerializedConf(_packs, true)
	if err != nil {
		return fmt.Errorf("error serializing packs %w", err)
	}
	// Update schedule in environment
	if err := environment.UpdatePacks(name, indentedPacks); err != nil {
		return fmt.Errorf("error updating packs %w", err)
	}
	// Refresh all configuration
	if err := environment.RefreshConfiguration(name); err != nil {
		return fmt.Errorf("error refreshing configuration %w", err)
	}
	return nil
}

// AddQueryToPackConf to add a new query to an existing pack in the osquery configuration
func (environment *EnvironmentManager) AddQueryToPackConf(name, pName, qName string, query ScheduleQuery) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	// Parse packs into struct
	_packs, err := environment.GenStructPacks([]byte(env.Packs))
	if err != nil {
		return fmt.Errorf("error structuring packs %w", err)
	}
	// Get pack to add the query
	pack := _packs[pName].(PackEntry)
	pack.Queries[qName] = query
	_packs[pName] = pack
	// Generate serialized indented packs
	indentedPacks, err := environment.GenSerializedConf(_packs, true)
	if err != nil {
		return fmt.Errorf("error serializing packs %w", err)
	}
	// Update schedule in environment
	if err := environment.UpdatePacks(name, indentedPacks); err != nil {
		return fmt.Errorf("error updating packs %w", err)
	}
	// Refresh all configuration
	if err := environment.RefreshConfiguration(name); err != nil {
		return fmt.Errorf("error refreshing configuration %w", err)
	}
	return nil
}

// RemoveQueryFromPackConf to remove a query from an existing query pack in the osquery configuration
func (environment *EnvironmentManager) RemoveQueryFromPackConf(name, pName, qName string) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	// Parse packs into struct
	_packs, err := environment.GenStructPacks([]byte(env.Packs))
	if err != nil {
		return fmt.Errorf("error structuring packs %w", err)
	}
	// Get pack to remove the query
	pack := _packs[pName].(PackEntry)
	delete(pack.Queries, qName)
	_packs[pName] = pack
	// Generate serialized indented packs
	indentedPacks, err := environment.GenSerializedConf(_packs, true)
	if err != nil {
		return fmt.Errorf("error serializing packs %w", err)
	}
	// Update schedule in environment
	if err := environment.UpdatePacks(name, indentedPacks); err != nil {
		return fmt.Errorf("error updating packs %w", err)
	}
	// Refresh all configuration
	if err := environment.RefreshConfiguration(name); err != nil {
		return fmt.Errorf("error refreshing configuration %w", err)
	}
	return nil
}
