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
func (environment *EnvManager) RefreshConfiguration(idEnv string) error {
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
func (environment *EnvManager) UpdateConfiguration(idEnv string, cnf OsqueryConf) error {
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
func (environment *EnvManager) UpdateConfigurationParts(idEnv string, cnf OsqueryConf) error {
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
func (environment *EnvManager) GenSerializedConf(structured interface{}, indent bool) (string, error) {
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
func (environment *EnvManager) GenStructConf(configuration []byte) (OsqueryConf, error) {
	var data OsqueryConf
	if err := json.Unmarshal(configuration, &data); err != nil {
		return data, err
	}
	return data, nil
}

// GenStructOptions to generate options from the serialized string
func (environment *EnvManager) GenStructOptions(configuration []byte) (OptionsConf, error) {
	var data OptionsConf
	if err := json.Unmarshal(configuration, &data); err != nil {
		return data, err
	}
	return data, nil
}

// GenStructSchedule to generate schedule from the serialized string
func (environment *EnvManager) GenStructSchedule(configuration []byte) (ScheduleConf, error) {
	var data ScheduleConf
	if err := json.Unmarshal(configuration, &data); err != nil {
		return data, err
	}
	return data, nil
}

// NodeStructSchedule to generate schedule that applies to a platform from the serialized string
func (environment *EnvManager) NodeStructSchedule(configuration []byte, platform string) (ScheduleConf, error) {
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
func (environment *EnvManager) GenStructPacks(configuration []byte) (PacksConf, error) {
	var data PacksConf
	if err := json.Unmarshal(configuration, &data); err != nil {
		return data, err
	}
	return data, nil
}

// NodePacksEntries to generate packs parsed struct that applies to a platform from the serialized string
func (environment *EnvManager) NodePacksEntries(configuration []byte, platform string) (PacksEntries, error) {
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
func (environment *EnvManager) GenPacksEntries(configuration []byte) (PacksEntries, error) {
	packsConf, err := environment.GenStructPacks(configuration)
	if err != nil {
		return PacksEntries{}, fmt.Errorf("in GenStructPacks %w", err)
	}
	packsEntries := make(PacksEntries)
	for k, p := range packsConf {
		switch v := p.(type) {
		case string:
			// This is a local pack, do nothing
		default:
			rawdata, err := json.Marshal(v)
			if err != nil {
				return PacksEntries{}, fmt.Errorf("in Marshal %w", err)
			}
			var parsed PackEntry
			if err := json.Unmarshal(rawdata, &parsed); err != nil {
				return PacksEntries{}, fmt.Errorf("in Unmarshal %w", err)
			}
			packsEntries[k] = parsed
		}
	}
	return packsEntries, nil
}

// GenStructDecorators to generate decorators from the serialized string
func (environment *EnvManager) GenStructDecorators(configuration []byte) (DecoratorConf, error) {
	var data DecoratorConf
	if err := json.Unmarshal(configuration, &data); err != nil {
		return data, err
	}
	return data, nil
}

// GenStructATC to generate ATC from the serialized string
func (environment *EnvManager) GenStructATC(configuration []byte) (ATCConf, error) {
	var data ATCConf
	if err := json.Unmarshal(configuration, &data); err != nil {
		return data, err
	}
	return data, nil
}

// GenEmptyConfiguration to generate a serialized string with an empty configuration
func (environment *EnvManager) GenEmptyConfiguration(indent bool) string {
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

// Configuration sections EditSection and the pure edit functions work on.
const (
	SectionOptions    = "options"
	SectionSchedule   = "schedule"
	SectionPacks      = "packs"
	SectionDecorators = "decorators"
	SectionATC        = "atc"
)

// EditSection reads one stored configuration section of environment name,
// applies edit to it, stores the result and refreshes the assembled
// configuration. Errors from edit are returned as they are.
func (environment *EnvManager) EditSection(name, section string, edit func(current string) (string, error)) error {
	env, err := environment.Get(name)
	if err != nil {
		return fmt.Errorf("error getting environment %w", err)
	}
	var current string
	var update func(string, string) error
	switch section {
	case SectionOptions:
		current, update = env.Options, environment.UpdateOptions
	case SectionSchedule:
		current, update = env.Schedule, environment.UpdateSchedule
	case SectionPacks:
		current, update = env.Packs, environment.UpdatePacks
	case SectionDecorators:
		current, update = env.Decorators, environment.UpdateDecorators
	case SectionATC:
		current, update = env.ATC, environment.UpdateATC
	default:
		return fmt.Errorf("unknown configuration section %q", section)
	}
	updated, err := edit(current)
	if err != nil {
		return err
	}
	if err := update(name, updated); err != nil {
		return fmt.Errorf("error updating %s %w", section, err)
	}
	// The section is stored; a failure here means another stored section is
	// malformed and the assembled configuration was not rebuilt.
	if err := environment.RefreshConfiguration(name); err != nil {
		return fmt.Errorf("%s saved, but refreshing the assembled configuration failed: %w", section, err)
	}
	return nil
}

// parseSection decodes a stored section. Empty and "null" are an empty
// section; anything that is not a JSON object is an error.
func parseSection[M ~map[string]V, V any](section, current string) (M, error) {
	var m M
	if s := strings.TrimSpace(current); s != "" {
		if err := json.Unmarshal([]byte(s), &m); err != nil {
			return nil, fmt.Errorf("error structuring %s %w", section, err)
		}
	}
	if m == nil {
		m = M{}
	}
	return m, nil
}

// serializeSection is the stored (indented) form of a section.
func serializeSection(section string, v interface{}) (string, error) {
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", fmt.Errorf("error serializing %s %w", section, err)
	}
	return string(out), nil
}

// SetOption returns options section current with option set to value.
func SetOption(current, option string, value interface{}) (string, error) {
	options, err := parseSection[OptionsConf](SectionOptions, current)
	if err != nil {
		return "", err
	}
	options[option] = value
	return serializeSection(SectionOptions, options)
}

// RemoveOption returns options section current without option.
func RemoveOption(current, option string) (string, error) {
	options, err := parseSection[OptionsConf](SectionOptions, current)
	if err != nil {
		return "", err
	}
	delete(options, option)
	return serializeSection(SectionOptions, options)
}

// AddScheduleQueries returns schedule section current with queries added or replaced.
func AddScheduleQueries(current string, queries ScheduleConf) (string, error) {
	schedule, err := parseSection[ScheduleConf](SectionSchedule, current)
	if err != nil {
		return "", err
	}
	for qName, query := range queries {
		schedule[qName] = query
	}
	return serializeSection(SectionSchedule, schedule)
}

// RemoveScheduleQuery returns schedule section current without query qName.
func RemoveScheduleQuery(current, qName string) (string, error) {
	schedule, err := parseSection[ScheduleConf](SectionSchedule, current)
	if err != nil {
		return "", err
	}
	delete(schedule, qName)
	return serializeSection(SectionSchedule, schedule)
}

// SetPack returns packs section current with pack pName set to pack (a
// PackEntry, or a path string for a local pack).
func SetPack(current, pName string, pack interface{}) (string, error) {
	packs, err := parseSection[PacksConf](SectionPacks, current)
	if err != nil {
		return "", err
	}
	packs[pName] = pack
	return serializeSection(SectionPacks, packs)
}

// RemovePack returns packs section current without pack pName.
func RemovePack(current, pName string) (string, error) {
	packs, err := parseSection[PacksConf](SectionPacks, current)
	if err != nil {
		return "", err
	}
	delete(packs, pName)
	return serializeSection(SectionPacks, packs)
}

// AddQueryToPack returns packs section current with query qName added to
// pack pName. Keys of the pack, and of an existing query, that this package
// does not model are kept.
func AddQueryToPack(current, pName, qName string, query ScheduleQuery) (string, error) {
	packs, err := parseSection[PacksConf](SectionPacks, current)
	if err != nil {
		return "", err
	}
	_, qs, err := packQueries(packs, pName)
	if err != nil {
		return "", err
	}
	rawQuery, err := json.Marshal(query)
	if err != nil {
		return "", fmt.Errorf("error encoding query - %w", err)
	}
	var qv map[string]interface{}
	if err := json.Unmarshal(rawQuery, &qv); err != nil {
		return "", fmt.Errorf("error encoding query - %w", err)
	}
	// Keep keys of an existing query that the new definition does not set
	if old, ok := qs[qName].(map[string]interface{}); ok {
		for k, v := range old {
			if _, set := qv[k]; !set {
				qv[k] = v
			}
		}
	}
	qs[qName] = qv
	return serializeSection(SectionPacks, packs)
}

// RemoveQueryFromPack returns packs section current without query qName in pack pName.
func RemoveQueryFromPack(current, pName, qName string) (string, error) {
	packs, err := parseSection[PacksConf](SectionPacks, current)
	if err != nil {
		return "", err
	}
	_, qs, err := packQueries(packs, pName)
	if err != nil {
		return "", err
	}
	delete(qs, qName)
	return serializeSection(SectionPacks, packs)
}

// AddOptionsConf to add an osquery option to the configuration
func (environment *EnvManager) AddOptionsConf(name, option string, value interface{}) error {
	return environment.EditSection(name, SectionOptions, func(c string) (string, error) { return SetOption(c, option, value) })
}

// RemoveOptionsConf to remove an osquery option from the configuration
func (environment *EnvManager) RemoveOptionsConf(name, option string) error {
	return environment.EditSection(name, SectionOptions, func(c string) (string, error) { return RemoveOption(c, option) })
}

// AddScheduleConfQuery to add a new query to the osquery schedule
func (environment *EnvManager) AddScheduleConfQuery(name, qName string, query ScheduleQuery) error {
	return environment.AddScheduleConfQueries(name, ScheduleConf{qName: query})
}

// AddScheduleConfQueries merges multiple queries into the osquery schedule.
func (environment *EnvManager) AddScheduleConfQueries(name string, queries ScheduleConf) error {
	return environment.EditSection(name, SectionSchedule, func(c string) (string, error) { return AddScheduleQueries(c, queries) })
}

// RemoveScheduleConfQuery to remove a query from the osquery schedule
func (environment *EnvManager) RemoveScheduleConfQuery(name, qName string) error {
	return environment.EditSection(name, SectionSchedule, func(c string) (string, error) { return RemoveScheduleQuery(c, qName) })
}

// AddQueryPackConf to add a new query pack to the osquery configuration
func (environment *EnvManager) AddQueryPackConf(name, pName string, pack interface{}) error {
	return environment.EditSection(name, SectionPacks, func(c string) (string, error) { return SetPack(c, pName, pack) })
}

// RemoveQueryPackConf to remove a query pack from the osquery configuration
func (environment *EnvManager) RemoveQueryPackConf(name, pName string) error {
	return environment.EditSection(name, SectionPacks, func(c string) (string, error) { return RemovePack(c, pName) })
}

// packQueries returns pack pName and its queries as generic maps, so editing
// a query keeps every key this package does not model. A missing "queries" is
// created. GenStructPacks decodes JSON, so a pack is a map or, for a local
// pack, a string path.
func packQueries(packs PacksConf, pName string) (map[string]interface{}, map[string]interface{}, error) {
	raw, ok := packs[pName]
	if !ok {
		return nil, nil, fmt.Errorf("pack %s not found", pName)
	}
	pack, ok := raw.(map[string]interface{})
	if !ok {
		if _, isPath := raw.(string); isPath {
			return nil, nil, fmt.Errorf("pack %s is a local pack (a file path) and has no queries to edit", pName)
		}
		return nil, nil, fmt.Errorf("pack %s is not a valid pack", pName)
	}
	qs, ok := pack["queries"].(map[string]interface{})
	if !ok {
		if pack["queries"] != nil {
			return nil, nil, fmt.Errorf("pack %s has invalid queries", pName)
		}
		qs = map[string]interface{}{}
		pack["queries"] = qs
	}
	return pack, qs, nil
}

// AddQueryToPackConf to add a new query to an existing pack in the osquery configuration
func (environment *EnvManager) AddQueryToPackConf(name, pName, qName string, query ScheduleQuery) error {
	return environment.EditSection(name, SectionPacks, func(c string) (string, error) { return AddQueryToPack(c, pName, qName, query) })
}

// RemoveQueryFromPackConf to remove a query from an existing query pack in the osquery configuration
func (environment *EnvManager) RemoveQueryFromPackConf(name, pName, qName string) error {
	return environment.EditSection(name, SectionPacks, func(c string) (string, error) { return RemoveQueryFromPack(c, pName, qName) })
}
