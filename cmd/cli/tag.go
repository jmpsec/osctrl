package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/jmpsec/osctrl/pkg/environments"
	"github.com/jmpsec/osctrl/pkg/tags"
	"github.com/olekukonko/tablewriter"
	"github.com/urfave/cli/v3"
)

// Helper function to convert a slice of tags into the data expected for output
func tagsToData(tgs []tags.AdminTag, m environments.MapEnvByID, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	for _, n := range tgs {
		data = append(data, tagToData(n, m, nil)...)
	}
	return data
}

// Helper function to convert a tag into the data expected for output
func tagToData(t tags.AdminTag, m environments.MapEnvByID, header []string) [][]string {
	var data [][]string
	if header != nil {
		data = append(data, header)
	}
	_t := []string{
		t.CreatedAt.String(),
		t.Name,
		t.Description,
		t.Color,
		t.Icon,
		m[t.EnvironmentID].Name,
		t.CreatedBy,
		stringifyBool(t.AutoTag),
		tags.TagTypeDecorator(t.TagType),
		t.CustomTag,
		stringifyBool(t.Sensitive),
	}
	data = append(data, _t)
	return data
}

func addTag(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	env := cmd.String("env")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	name := cmd.String("name")
	if name == "" {
		fmt.Println("❌ tag name is required")
		os.Exit(1)
	}
	color := cmd.String("color")
	if color == "" {
		color = tags.RandomColor()
	} else if !strings.HasPrefix(color, "#") || len(color) != 7 {
		fmt.Println("❌ color must be a hex value starting with # and 6 characters long (e.g. #FF5733)")
		os.Exit(1)
	}
	icon := cmd.String("icon")
	if icon == "" {
		icon = tags.DefaultTagIcon
	}
	description := cmd.String("description")
	tagType := tags.TagTypeParser(cmd.String("tag-type"))
	tagCustom := cmd.String("tag-custom")
	sensitive := cmd.Bool("sensitive")
	if tagType == tags.TagTypeCustom && tagCustom == "" {
		fmt.Println("❌ tag custom value is required when tag type is set to 'custom'")
		os.Exit(1)
	}
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("error env get - %w", err)
		}
		// TODO - Use the correct user
		if err := tagsmgr.NewTag(name, description, color, icon, appName, e.ID, false, tagType, tags.SetCustomTag(tagType, tagCustom)); err != nil {
			return fmt.Errorf("%w", err)
		}
		// Audit log
		if sensitive {
			// a new tag has no scope grants to remove
			t, err := tagsmgr.Get(name, e.ID)
			if err != nil {
				return fmt.Errorf("%w", err)
			}
			if err := tagsmgr.ChangeSensitive(&t, true); err != nil {
				return fmt.Errorf("%w", err)
			}
		}
		note := ""
		if sensitive {
			note = " (sensitive=true)"
		}
		auditlogsmgr.TagAction(getShellUsername(), "add tag "+name+note, "CLI", e.ID)
	} else if apiFlag {
		var sens *bool
		if sensitive {
			sens = &sensitive
		}
		_, err := osctrlAPI.AddTag(env, name, color, icon, description, tagType, tags.SetCustomTag(tagType, tagCustom), sens)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ tag %s created successfully\n", name)
	}
	return nil
}

func deleteTag(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	env := cmd.String("env-uuid")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	name := cmd.String("name")
	if name == "" {
		fmt.Println("❌ tag name is required")
		os.Exit(1)
	}
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("error env get - %w", err)
		}
		if err := tagsmgr.DeleteGet(name, e.ID); err != nil {
			return fmt.Errorf("%w", err)
		}
		// Audit log
		auditlogsmgr.TagAction(getShellUsername(), "delete tag "+name, "CLI", e.ID)
	} else if apiFlag {
		_, err := osctrlAPI.DeleteTag(env, name)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ tag %s deleted successfully\n", name)
	}
	return nil
}

func editTag(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	env := cmd.String("env-uuid")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	name := cmd.String("name")
	if name == "" {
		fmt.Println("❌ tag name is required")
		os.Exit(1)
	}
	if cmd.IsSet("color") {
		if c := cmd.String("color"); !strings.HasPrefix(c, "#") || len(c) != 7 {
			fmt.Println("❌ color must be a hex value starting with # and 6 characters long (e.g. #FF5733)")
			os.Exit(1)
		}
	}
	if cmd.IsSet("tag-type") && tags.TagTypeParser(cmd.String("tag-type")) == tags.TagTypeCustom && cmd.String("tag-custom") == "" {
		fmt.Println("❌ tag custom value is required when tag type is set to 'custom'")
		os.Exit(1)
	}
	// nil leaves the flag unchanged
	var sens *bool
	if cmd.IsSet("sensitive") {
		v := cmd.Bool("sensitive")
		sens = &v
	}
	// Retrieve the stored tag: every field the operator did not set keeps its value
	var t tags.AdminTag
	var envID uint
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("error env get - %w", err)
		}
		envID = e.ID
		t, err = tagsmgr.Get(name, e.ID)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
	} else if apiFlag {
		var err error
		t, err = osctrlAPI.GetTag(env, name)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	color, icon, description := t.Color, t.Icon, t.Description
	tagType, tagCustom := t.TagType, t.CustomTag
	if cmd.IsSet("color") {
		color = cmd.String("color")
	}
	if cmd.IsSet("icon") {
		icon = cmd.String("icon")
	}
	if cmd.IsSet("description") {
		description = cmd.String("description")
	}
	if cmd.IsSet("tag-type") {
		tagType = tags.TagTypeParser(cmd.String("tag-type"))
		tagCustom = ""
	}
	if cmd.IsSet("tag-custom") {
		tagCustom = cmd.String("tag-custom")
	}
	if cmd.IsSet("tag-type") || cmd.IsSet("tag-custom") {
		tagCustom = tags.SetCustomTag(tagType, tagCustom)
	}
	if dbFlag {
		if description != t.Description {
			if err := tagsmgr.ChangeDescription(&t, description); err != nil {
				return fmt.Errorf("%w", err)
			}
		}
		if color != t.Color {
			if err := tagsmgr.ChangeColor(&t, color); err != nil {
				return fmt.Errorf("%w", err)
			}
		}
		if icon != t.Icon {
			if err := tagsmgr.ChangeIcon(&t, icon); err != nil {
				return fmt.Errorf("%w", err)
			}
		}
		if tagType != t.TagType {
			if err := tagsmgr.ChangeTagType(&t, tagType); err != nil {
				return fmt.Errorf("%w", err)
			}
		}
		if tagCustom != t.CustomTag {
			if err := tagsmgr.ChangeCustom(&t, tagCustom); err != nil {
				return fmt.Errorf("%w", err)
			}
		}
		auditNote := ""
		if sens != nil {
			if *sens != t.Sensitive {
				if err := tagsmgr.ChangeSensitive(&t, *sens); err != nil {
					return fmt.Errorf("%w", err)
				}
				auditNote = fmt.Sprintf(" (sensitive=%t)", *sens)
			}
			if *sens {
				// mirror the API: a sensitive tag cannot stay in a scope grant (idempotent, so a retry heals)
				if err := adminUsers.DeleteScopeTagsForTag(t.ID); err != nil {
					return fmt.Errorf("%w", err)
				}
			}
		}
		// Audit log
		auditlogsmgr.TagAction(getShellUsername(), "edit tag "+name+auditNote, "CLI", envID)
	} else if apiFlag {
		_, err := osctrlAPI.EditTag(env, name, color, icon, description, tagType, tagCustom, sens)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	if !silentFlag {
		fmt.Printf("✅ tag %s updated successfully\n", name)
	}
	return nil
}

func showTag(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	env := cmd.String("env-uuid")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	name := cmd.String("name")
	if name == "" {
		fmt.Println("❌ tag name is required")
		os.Exit(1)
	}
	var t tags.AdminTag
	var envName string
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("error env get - %w", err)
		}
		t, err = tagsmgr.Get(name, e.ID)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		envName = e.Name
	} else if apiFlag {
		t, err = osctrlAPI.GetTag(env, name)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		e, err := osctrlAPI.GetEnvironment(env)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		envName = e.Name
	}
	fmt.Printf("Tag: %s\n", t.Name)
	fmt.Printf("Description: %s\n", t.Description)
	fmt.Printf("Color: %s\n", t.Color)
	fmt.Printf("Icon: %s\n", t.Icon)
	fmt.Printf("Created: %s\n", t.CreatedAt.String())
	fmt.Printf("CreatedBy: %s\n", t.CreatedBy)
	fmt.Printf("AutoTag: %s\n", stringifyBool(t.AutoTag))
	fmt.Printf("TagType: %s\n", tags.TagTypeDecorator(t.TagType))
	fmt.Printf("Custom: %s\n", t.CustomTag)
	fmt.Printf("Sensitive: %s\n", stringifyBool(t.Sensitive))
	fmt.Printf("Environment: %s\n", envName)
	fmt.Println()
	return nil
}

func helperListTags(tgs []tags.AdminTag, m environments.MapEnvByID) error {
	header := []string{
		"Created",
		"Name",
		"Description",
		"Color",
		"Icon",
		"Environment",
		"CreatedBy",
		"AutoTag",
		"TagType",
		"CustomTag",
		"Sensitive",
	}
	// Prepare output
	switch formatFlag {
	case jsonFormat:
		jsonRaw, err := json.Marshal(tgs)
		if err != nil {
			return fmt.Errorf("error marshaling - %w", err)
		}
		fmt.Println(string(jsonRaw))
	case csvFormat:
		data := tagsToData(tgs, m, header)
		w := csv.NewWriter(os.Stdout)
		if err := w.WriteAll(data); err != nil {
			return fmt.Errorf("error writing csv - %w", err)
		}
	case prettyFormat:
		table := tablewriter.NewWriter(os.Stdout)
		table.Header(stringSliceToAnySlice(header)...)
		if len(tgs) > 0 {
			fmt.Printf("Existing tags (%d):\n", len(tgs))
			data := tagsToData(tgs, m, nil)
			if err := table.Bulk(data); err != nil {
				return fmt.Errorf("error bulk table - %w", err)
			}
		} else {
			fmt.Println("No tags")
		}
		if err := table.Render(); err != nil {
			return fmt.Errorf("error rendering table - %w", err)
		}
	}
	return nil
}

func listTagsByEnv(ctx context.Context, cmd *cli.Command) error {
	// Get values from flags
	env := cmd.String("env-uuid")
	if env == "" {
		fmt.Println("❌ environment is required")
		os.Exit(1)
	}
	// Retrieve data
	var tgs []tags.AdminTag
	var m environments.MapEnvByID
	if dbFlag {
		e, err := envs.Get(env)
		if err != nil {
			return fmt.Errorf("error env get - %w", err)
		}
		tgs, err = tagsmgr.GetByEnv(e.ID)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		m, err = envs.GetMapByID()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
	} else if apiFlag {
		tgs, err = osctrlAPI.GetTags(env)
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		m, err = osctrlAPI.GetEnvMap()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	if err := helperListTags(tgs, m); err != nil {
		return fmt.Errorf("%w", err)
	}
	return nil
}

func listAllTags(ctx context.Context, cmd *cli.Command) error {
	var tgs []tags.AdminTag
	var m environments.MapEnvByID
	if dbFlag {
		tgs, err = tagsmgr.All()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		m, err = envs.GetMapByID()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
	} else if apiFlag {
		tgs, err = osctrlAPI.GetAllTags()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
		m, err = osctrlAPI.GetEnvMap()
		if err != nil {
			return fmt.Errorf("%w", err)
		}
	}
	if err := helperListTags(tgs, m); err != nil {
		return fmt.Errorf("%w", err)
	}
	return nil
}
