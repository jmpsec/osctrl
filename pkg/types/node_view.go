package types

import (
	"encoding/json"

	"github.com/jmpsec/osctrl/pkg/nodes"
)

// SPA-facing node projections that surface the parsed-and-sanitized subset of
// nodes.OsqueryNode.RawEnrollment (the JSON blob osquery sends during enroll).
// RawEnrollment itself stays `json:"-"` on the DB model because it contains the
// env's enroll_secret. Everything below is the safe-to-expose subset.
//
// Why a separate projection rather than adding JSON tags to RawEnrollment:
//   - Selective exposure: the enroll payload includes `enroll_secret`; we MUST
//     drop it. Surface-by-surface field allowlisting is safer than blacklisting
//     a single key on a `map[string]interface{}`.
//   - Versioning: osquery's enrollment payload is osquery-side schema, not
//     osctrl-side. If a future osquery release adds a field, we don't leak it
//     until we explicitly add it here.
//   - Backward compat: existing API consumers see exactly the same OsqueryNode
//     shape they always did — `system_info` is an *additional* field with
//     `omitempty`, so when parsing fails or the node has no raw enrollment it
//     simply disappears.

// SystemInfo mirrors host_details.system_info from the osquery enroll payload,
// minus the host_identifier / instance_id fields which are duplicates of data
// we already expose via OsqueryNode.UUID.
type SystemInfo struct {
	HardwareVendor   string `json:"hardware_vendor,omitempty"`
	HardwareModel    string `json:"hardware_model,omitempty"`
	HardwareVersion  string `json:"hardware_version,omitempty"`
	HardwareSerial   string `json:"hardware_serial,omitempty"`
	CPUBrand         string `json:"cpu_brand,omitempty"`
	CPUType          string `json:"cpu_type,omitempty"`
	CPUSubtype       string `json:"cpu_subtype,omitempty"`
	CPUPhysicalCores string `json:"cpu_physical_cores,omitempty"`
	CPULogicalCores  string `json:"cpu_logical_cores,omitempty"`
	PhysicalMemory   string `json:"physical_memory,omitempty"`
	ComputerName     string `json:"computer_name,omitempty"`
	LocalHostname    string `json:"local_hostname,omitempty"`
}

// BIOSInfo mirrors host_details.platform_info from the osquery enroll payload.
// "Platform info" in osquery's vocabulary is BIOS / firmware metadata; renamed
// here so the SPA naming aligns with what an operator expects to read.
type BIOSInfo struct {
	Vendor     string `json:"vendor,omitempty"`
	Version    string `json:"version,omitempty"`
	Date       string `json:"date,omitempty"`
	Revision   string `json:"revision,omitempty"`
	Address    string `json:"address,omitempty"`
	Size       string `json:"size,omitempty"`
	VolumeSize string `json:"volume_size,omitempty"`
}

// OSInfo mirrors host_details.os_version. Adds the few fields beyond what
// OsqueryNode.Platform / PlatformVersion already expose (codename, family).
type OSInfo struct {
	Name         string `json:"name,omitempty"`
	Version      string `json:"version,omitempty"`
	Codename     string `json:"codename,omitempty"`
	Major        string `json:"major,omitempty"`
	Minor        string `json:"minor,omitempty"`
	Patch        string `json:"patch,omitempty"`
	Platform     string `json:"platform,omitempty"`
	PlatformLike string `json:"platform_like,omitempty"`
}

// OsqueryRuntime mirrors host_details.osquery_info — the runtime / build
// metadata of the agent that enrolled. Useful for "this node is running an
// extensions-disabled build" diagnostics. Drops `instance_id`, `pid`, and
// `watcher` (PIDs) since they leak less-useful runtime detail; keep
// `start_time` so operators can see when the daemon last restarted.
type OsqueryRuntime struct {
	Version       string `json:"version,omitempty"`
	BuildPlatform string `json:"build_platform,omitempty"`
	BuildDistro   string `json:"build_distro,omitempty"`
	Extensions    string `json:"extensions,omitempty"`
	StartTime     string `json:"start_time,omitempty"`
	ConfigValid   string `json:"config_valid,omitempty"`
}

// NodeEnrichment is the projected view of everything we want to expose from
// nodes.OsqueryNode.RawEnrollment that isn't already on OsqueryNode itself.
// Embedded into NodeView with `json:"system_info,omitempty"` — the outer key
// is a slight abuse of the name (it carries BIOS + OS + runtime too) but it
// matches the heaviest sub-object and reads well in the SPA.
type NodeEnrichment struct {
	System  *SystemInfo     `json:"system,omitempty"`
	BIOS    *BIOSInfo       `json:"bios,omitempty"`
	OS      *OSInfo         `json:"os,omitempty"`
	Osquery *OsqueryRuntime `json:"osquery,omitempty"`
}

// NodeView is the JSON shape returned by the node show + list endpoints.
// It embeds OsqueryNode verbatim (so existing JSON fields stay) and adds the
// optional enrichment block. Consumers that don't care about the enrichment
// (CLI, dashboards) ignore the extra field; the SPA's Node Detail page reads
// from it directly.
type NodeView struct {
	nodes.OsqueryNode
	Enrichment *NodeEnrichment `json:"system_info,omitempty"`
}

// ProjectNode wraps a single OsqueryNode into the SPA-facing NodeView, parsing
// RawEnrollment best-effort. A parse failure or an absent payload simply
// leaves Enrichment nil — the JSON `omitempty` then drops the key entirely so
// the SPA sees the same `OsqueryNode` shape it always saw, plus optional
// detail when available.
func ProjectNode(n nodes.OsqueryNode) NodeView {
	view := NodeView{OsqueryNode: n}
	if n.RawEnrollment == "" {
		return view
	}
	// Parse into an intermediate map-of-maps because osquery's enroll payload
	// shape is osquery-side and we don't want to maintain a parallel Go struct
	// for every key. We only read the few keys we need.
	var outer struct {
		HostDetails struct {
			SystemInfo   map[string]string `json:"system_info"`
			PlatformInfo map[string]string `json:"platform_info"`
			OSVersion    map[string]string `json:"os_version"`
			OsqueryInfo  map[string]string `json:"osquery_info"`
		} `json:"host_details"`
	}
	if err := json.Unmarshal([]byte(n.RawEnrollment), &outer); err != nil {
		// Malformed payload — return the bare node, don't fail the request.
		return view
	}
	enr := &NodeEnrichment{}
	if si := outer.HostDetails.SystemInfo; len(si) > 0 {
		enr.System = &SystemInfo{
			HardwareVendor:   si["hardware_vendor"],
			HardwareModel:    si["hardware_model"],
			HardwareVersion:  si["hardware_version"],
			HardwareSerial:   si["hardware_serial"],
			CPUBrand:         si["cpu_brand"],
			CPUType:          si["cpu_type"],
			CPUSubtype:       si["cpu_subtype"],
			CPUPhysicalCores: si["cpu_physical_cores"],
			CPULogicalCores:  si["cpu_logical_cores"],
			PhysicalMemory:   si["physical_memory"],
			ComputerName:     si["computer_name"],
			LocalHostname:    si["local_hostname"],
		}
	}
	if pi := outer.HostDetails.PlatformInfo; len(pi) > 0 {
		enr.BIOS = &BIOSInfo{
			Vendor:     pi["vendor"],
			Version:    pi["version"],
			Date:       pi["date"],
			Revision:   pi["revision"],
			Address:    pi["address"],
			Size:       pi["size"],
			VolumeSize: pi["volume_size"],
		}
	}
	if ov := outer.HostDetails.OSVersion; len(ov) > 0 {
		enr.OS = &OSInfo{
			Name:         ov["name"],
			Version:      ov["version"],
			Codename:     ov["codename"],
			Major:        ov["major"],
			Minor:        ov["minor"],
			Patch:        ov["patch"],
			Platform:     ov["platform"],
			PlatformLike: ov["platform_like"],
		}
	}
	if oi := outer.HostDetails.OsqueryInfo; len(oi) > 0 {
		enr.Osquery = &OsqueryRuntime{
			Version:       oi["version"],
			BuildPlatform: oi["build_platform"],
			BuildDistro:   oi["build_distro"],
			Extensions:    oi["extensions"],
			StartTime:     oi["start_time"],
			ConfigValid:   oi["config_valid"],
		}
	}
	// Drop the enrichment block entirely when nothing was populated, so that a
	// node with empty/whitespace RawEnrollment doesn't leak a "system_info: {}"
	// shell that misleads operators into thinking we have data we don't.
	if enr.System == nil && enr.BIOS == nil && enr.OS == nil && enr.Osquery == nil {
		return view
	}
	view.Enrichment = enr
	return view
}

// ProjectNodes wraps a slice with ProjectNode — used by the list endpoint to
// keep the table-row payload consistent with the show endpoint.
func ProjectNodes(in []nodes.OsqueryNode) []NodeView {
	out := make([]NodeView, len(in))
	for i, n := range in {
		out[i] = ProjectNode(n)
	}
	return out
}
