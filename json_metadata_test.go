package luks

import (
	"encoding/json"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func parseMetadata(t *testing.T, filename string) {
	data, err := os.ReadFile(filename)
	require.NoError(t, err)

	var meta metadata
	require.NoError(t, json.Unmarshal(data, &meta))
	require.Equal(t, uint(4000), meta.Keyslots[0].Af.Stripes)
}

func TestParseMetadata(t *testing.T) {
	parseMetadata(t, "testdata/metadata/1.json")
	parseMetadata(t, "testdata/metadata/2.json")
}

// TestConfigRequirementsArray verifies parsing of requirements as a JSON array
// of strings, which is the form documented in the LUKS2 on-disk format spec.
func TestConfigRequirementsArray(t *testing.T) {
	data, err := os.ReadFile("testdata/metadata/requirements_array.json")
	require.NoError(t, err)

	var meta metadata
	require.NoError(t, json.Unmarshal(data, &meta))
	require.ElementsMatch(t, []string{"opal", "inline-hw-tags"}, []string(meta.Config.Requirements))
}

// TestConfigRequirementsObject verifies parsing of requirements as a JSON object
// {"mandatory": [...]}, which is the form that cryptsetup actually emits (issue #14).
func TestConfigRequirementsObject(t *testing.T) {
	data, err := os.ReadFile("testdata/metadata/requirements_object.json")
	require.NoError(t, err)

	var meta metadata
	require.NoError(t, json.Unmarshal(data, &meta))
	require.ElementsMatch(t, []string{"opal"}, []string(meta.Config.Requirements))
}

// TestConfigRequirementsAbsent verifies that an absent requirements field
// results in a nil/empty slice without error.
func TestConfigRequirementsAbsent(t *testing.T) {
	// testdata/metadata/2.json has no requirements field
	data, err := os.ReadFile("testdata/metadata/2.json")
	require.NoError(t, err)

	var meta metadata
	require.NoError(t, json.Unmarshal(data, &meta))
	require.Empty(t, meta.Config.Requirements)
}

// TestSegmentFlags verifies that optional segment flags are parsed correctly.
func TestSegmentFlags(t *testing.T) {
	data, err := os.ReadFile("testdata/metadata/segment_flags.json")
	require.NoError(t, err)

	var meta metadata
	require.NoError(t, json.Unmarshal(data, &meta))
	require.Equal(t, []string{"in-reencryption"}, meta.Segments[0].Flags)
}

// TestSegmentFlagsAbsent verifies that a segment without flags parses without error.
func TestSegmentFlagsAbsent(t *testing.T) {
	// testdata/metadata/1.json has a segment without flags
	data, err := os.ReadFile("testdata/metadata/1.json")
	require.NoError(t, err)

	var meta metadata
	require.NoError(t, json.Unmarshal(data, &meta))
	require.Nil(t, meta.Segments[0].Flags)
}

// TestConfigFlags verifies that persistent config flags are parsed correctly.
func TestConfigFlags(t *testing.T) {
	// testdata/metadata/1.json has flags: ["allow-discards"]
	data, err := os.ReadFile("testdata/metadata/1.json")
	require.NoError(t, err)

	var meta metadata
	require.NoError(t, json.Unmarshal(data, &meta))
	require.Equal(t, []string{"allow-discards"}, meta.Config.Flags)
}

// TestConfigFlagsAbsent verifies that an absent flags field results in nil without error.
func TestConfigFlagsAbsent(t *testing.T) {
	// testdata/metadata/2.json has no flags field
	data, err := os.ReadFile("testdata/metadata/2.json")
	require.NoError(t, err)

	var meta metadata
	require.NoError(t, json.Unmarshal(data, &meta))
	require.Nil(t, meta.Config.Flags)
}

// TestRequirementsRoundtrip verifies that inline JSON with requirements in both
// formats is handled correctly.
func TestRequirementsRoundtrip(t *testing.T) {
	tests := []struct {
		name     string
		json     string
		expected []string
	}{
		{
			name:     "array form",
			json:     `{"json_size":"12288","keyslots_size":"4161536","requirements":["opal","online-reencrypt-v2"]}`,
			expected: []string{"opal", "online-reencrypt-v2"},
		},
		{
			name:     "object form",
			json:     `{"json_size":"12288","keyslots_size":"4161536","requirements":{"mandatory":["opal"]}}`,
			expected: []string{"opal"},
		},
		{
			name:     "absent",
			json:     `{"json_size":"12288","keyslots_size":"4161536"}`,
			expected: nil,
		},
		{
			name:     "empty array",
			json:     `{"json_size":"12288","keyslots_size":"4161536","requirements":[]}`,
			expected: []string{},
		},
		{
			name:     "empty mandatory object",
			json:     `{"json_size":"12288","keyslots_size":"4161536","requirements":{"mandatory":[]}}`,
			expected: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var cfg config
			require.NoError(t, json.Unmarshal([]byte(tc.json), &cfg))
			require.Equal(t, configRequirements(tc.expected), cfg.Requirements)
		})
	}
}
