package logsinks

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchesCategoryEmptyMeansAll(t *testing.T) {
	assert.True(t, MatchesCategory(nil, CatStatus))
	assert.True(t, MatchesCategory(nil, CatResult))
	assert.True(t, MatchesCategory(nil, CatQuery))
	assert.True(t, MatchesCategory(nil, CatCarveMeta))
	assert.True(t, MatchesCategory(nil, CatCarveData))
	assert.True(t, MatchesCategory([]string{}, CatStatus))
}

func TestMatchesCategoryExplicit(t *testing.T) {
	cats := []string{CatStatus, CatQuery}
	assert.True(t, MatchesCategory(cats, CatStatus))
	assert.True(t, MatchesCategory(cats, CatQuery))
	assert.False(t, MatchesCategory(cats, CatResult))
	assert.False(t, MatchesCategory(cats, CatCarveMeta))
	assert.False(t, MatchesCategory(cats, CatCarveData))
}

func TestValidateCategories(t *testing.T) {
	require.NoError(t, ValidateCategories(nil))
	require.NoError(t, ValidateCategories([]string{}))
	require.NoError(t, ValidateCategories([]string{CatStatus, CatResult}))
	require.NoError(t, ValidateCategories(AllCategories))

	err := ValidateCategories([]string{"bogus"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "bogus")
}

func TestNormalizeCategories(t *testing.T) {
	// Empty stays empty
	out, err := NormalizeCategories(nil)
	require.NoError(t, err)
	assert.Nil(t, out)

	// Subset stays as-is
	out, err = NormalizeCategories([]string{CatStatus, CatQuery})
	require.NoError(t, err)
	assert.Equal(t, []string{CatStatus, CatQuery}, out)

	// All five collapses to nil
	out, err = NormalizeCategories(AllCategories)
	require.NoError(t, err)
	assert.Nil(t, out)

	// Unknown is rejected
	_, err = NormalizeCategories([]string{"bogus"})
	require.Error(t, err)
}

func TestEncodeDecodeCategories(t *testing.T) {
	// Empty encodes as ""
	assert.Equal(t, "", encodeCategories(nil))
	assert.Equal(t, "", encodeCategories([]string{}))

	// Non-empty encodes as JSON array
	encoded := encodeCategories([]string{CatStatus, CatQuery})
	assert.Equal(t, `["status","query"]`, encoded)

	// Decode round-trips
	decoded := DecodeCategories(encoded)
	assert.Equal(t, []string{CatStatus, CatQuery}, decoded)

	// Decode empty returns nil
	assert.Nil(t, DecodeCategories(""))
}
