package lineaje

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetPURLWithoutQualifiers(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedOutput string
	}{
		{
			name:           "PURLWithQualifiers",
			input:          "pkg:type/namespace/name@version?qualifiers=key:value",
			expectedOutput: "pkg:type/namespace/name@version",
		},
		{
			name:           "PURLWithoutQualifiers",
			input:          "pkg:type/namespace/name@version",
			expectedOutput: "pkg:type/namespace/name@version",
		},
		{
			name:           "EmptyPURL",
			input:          "",
			expectedOutput: "",
		},
		{
			name:           "MalformedPURL",
			input:          "pkg:type/namespace@version?",
			expectedOutput: "pkg:type/namespace@version",
		},
		{
			name:           "MinimalPURL",
			input:          "pkg:type/name",
			expectedOutput: "pkg:type/name",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output := GetPURLWithoutQualifiers(tc.input)
			assert.Equal(t, tc.expectedOutput, output)
		})
	}
}

func TestConvertToResourceId(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		expectedOutput string
		expectError    bool
	}{
		{
			name:        "EmptyPURL",
			input:       "",
			expectError: true,
		},
		{
			name:           "ValidPURLWithoutNamespace",
			input:          "pkg:type/name@version",
			expectedOutput: "type:name:version",
			expectError:    false,
		},
		{
			name:           "ValidPURLWithNamespace",
			input:          "pkg:type/namespace/name@version",
			expectedOutput: "namespace:name:version",
			expectError:    false,
		},
		{
			name:           "ValidPURLWithoutVersion",
			input:          "pkg:type/namespace/name",
			expectedOutput: "namespace:name",
			expectError:    false,
		},
		{
			name:           "PURLWithoutName",
			input:          "pkg:type/namespace@version",
			expectedOutput: "type:namespace:version",
			expectError:    false,
		},
		{
			name:           "PURLWithoutNamespace",
			input:          "pkg:type/name@version",
			expectedOutput: "type:name:version",
			expectError:    false,
		},
		{
			name:        "MalformedPURL",
			input:       "pkg:type/@version",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			output, err := ConvertToResourceId(tc.input)

			if tc.expectError {
				assert.Error(t, err)
				assert.Contains(t, output, UnresolvedId)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedOutput, output)
			}
		})
	}
}

func TestGetBomRefForDuplicatePURL(t *testing.T) {
	tests := []struct {
		name           string
		purlsVsBomRef  map[string]string
		purlValue      string
		expectedOutput string
		expectError    bool
	}{
		{
			name:           "ValidPURLFoundInMap",
			purlsVsBomRef:  map[string]string{"pkg:type/name@version": "bom-ref-123"},
			purlValue:      "pkg:type/name@version",
			expectedOutput: "bom-ref-123",
			expectError:    false,
		},
		{
			name:           "ValidPURLNotFoundInMap",
			purlsVsBomRef:  map[string]string{"pkg:type/name@version": "bom-ref-123"},
			purlValue:      "pkg:type/othername@version",
			expectedOutput: "",
			expectError:    false,
		},
		{
			name:           "PURLWithQualifiers",
			purlsVsBomRef:  map[string]string{"pkg:type/name@version": "bom-ref-123"},
			purlValue:      "pkg:type/name@version?qualifiers=key:value",
			expectedOutput: "bom-ref-123",
			expectError:    false,
		},
		{
			name:           "EmptyPURLInput",
			purlsVsBomRef:  map[string]string{},
			purlValue:      "",
			expectedOutput: "",
			expectError:    true,
		},
		{
			name:           "MalformedPURLInput",
			purlsVsBomRef:  map[string]string{},
			purlValue:      "pkg:type:name?@",
			expectedOutput: "",
			expectError:    true,
		},
		{
			name:           "EmptyMapWithValidPURL",
			purlsVsBomRef:  map[string]string{},
			purlValue:      "pkg:type/name@version",
			expectedOutput: "",
			expectError:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err, output := GetBomRefForDuplicatePURL(tc.purlsVsBomRef, tc.purlValue)

			if tc.expectError {
				assert.Error(t, err)
				assert.Equal(t, tc.expectedOutput, output)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedOutput, output)
			}
		})
	}
}
