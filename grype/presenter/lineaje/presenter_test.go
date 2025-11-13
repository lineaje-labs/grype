package lineaje

import (
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/artifact"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestCreateDependencyMapForReport(t *testing.T) {
	tests := []struct {
		name           string
		input          map[string]*Set[string]
		expectedOutput []ComponentRelationship
	}{
		{
			name:           "Nil input",
			input:          nil,
			expectedOutput: []ComponentRelationship(nil),
		},
		{
			name:           "Empty input map",
			input:          map[string]*Set[string]{},
			expectedOutput: []ComponentRelationship(nil),
		},
		{
			name: "Single parent with no children",
			input: map[string]*Set[string]{
				"parent1": nil,
			},
			expectedOutput: []ComponentRelationship{
				{
					BomRef:    "parent1",
					DependsOn: *NewSet[string](),
				},
			},
		},
		{
			name: "Single parent with multiple children",
			input: map[string]*Set[string]{
				"parent1": NewSet[string]("child1", "child2"),
			},
			expectedOutput: []ComponentRelationship{
				{
					BomRef:    "parent1",
					DependsOn: *NewSet[string]("child1", "child2"),
				},
			},
		},
		{
			name: "Multiple parents with multiple children",
			input: map[string]*Set[string]{
				"parent1": NewSet[string]("child1", "child2"),
				"parent2": NewSet[string]("child3", "child4", "child5"),
			},
			expectedOutput: []ComponentRelationship{
				{
					BomRef:    "parent1",
					DependsOn: *NewSet[string]("child1", "child2"),
				},
				{
					BomRef:    "parent2",
					DependsOn: *NewSet[string]("child3", "child4", "child5"),
				},
			},
		},
		{
			name: "Parent with duplicate children",
			input: map[string]*Set[string]{
				"parent1": NewSet[string]("child1", "child1", "child2"),
			},
			expectedOutput: []ComponentRelationship{
				{
					BomRef:    "parent1",
					DependsOn: *NewSet[string]("child1", "child2"),
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			actual := createDependencyMapForReport(tc.input)
			sort.Slice(actual, func(i, j int) bool {
				return actual[i].BomRef < actual[j].BomRef
			})
			sort.Slice(tc.expectedOutput, func(i, j int) bool {
				return tc.expectedOutput[i].BomRef < tc.expectedOutput[j].BomRef
			})
			assert.Equal(t, tc.expectedOutput, actual)
		})
	}
}

func TestPresenter_Present(t *testing.T) {
	toPkg := func(str string, purlValue string, idValue string) syftPkg.Package {
		var typ, name, version string
		s := strings.Split(strings.TrimSpace(str), ":")
		if len(s) > 1 {
			typ = s[0]
			str = s[1]
		}
		s = strings.Split(str, "@")
		name = s[0]
		if len(s) > 1 {
			version = s[1]
		}

		p := syftPkg.Package{
			Type:    syftPkg.Type(typ),
			Name:    name,
			Version: version,
			PURL:    purlValue,
		}
		p.OverrideID(artifact.ID(idValue))

		return p
	}
	tests := []struct {
		name        string
		presenter   Presenter
		wantErr     bool
		outputCheck func(t *testing.T, output string)
	}{
		{
			name: "SBOM which is nil",
			presenter: Presenter{
				document: models.Document{
					StartTimestamp: time.Now().Local().Round(0).Format(time.RFC3339),
				},
				sbom:   nil,
				pretty: false,
			},
			wantErr: false,
			outputCheck: func(t *testing.T, output string) {
				assert.Contains(t, output, `"dependencies":null`)
			},
		},
		{
			name: "SBOM with no packages",
			presenter: Presenter{
				document: models.Document{
					StartTimestamp: time.Now().Local().Round(0).Format(time.RFC3339),
				},
				sbom:   &sbom.SBOM{},
				pretty: false,
			},
			wantErr: false,
			outputCheck: func(t *testing.T, output string) {
				assert.Contains(t, output, `"dependencies":null`)
			},
		},
		{
			name: "SBOM with relationships only",
			presenter: Presenter{
				document: models.Document{
					StartTimestamp: time.Now().Local().Round(0).Format(time.RFC3339),
				},
				sbom: &sbom.SBOM{
					Relationships: []artifact.Relationship{
						{
							Type: "dependency-of",
							From: toPkg(":child1@2.14.1", "", "child1-bom-ref"),
							To:   toPkg(":parent1@1.18", "", "parent1-bom-ref"),
						},
					},
				},
				pretty: false,
			},
			wantErr: false,
			outputCheck: func(t *testing.T, output string) {
				assert.Contains(t, output, `"dependencies":null`)
			},
		},
		{
			name: "SBOM with packages only",
			presenter: Presenter{
				document: models.Document{
					StartTimestamp: time.Now().Local().Round(0).Format(time.RFC3339),
				},
				sbom: &sbom.SBOM{
					Artifacts: sbom.Artifacts{
						Packages: syftPkg.NewCollection(
							toPkg(":child1@2.14.1", "", "child1-bom-ref"),
							toPkg(":parent1@1.18", "", "parent1-bom-ref"),
						),
					},
				},
				pretty: false,
			},
			wantErr: false,
			outputCheck: func(t *testing.T, output string) {
				assert.Contains(t, output, `"dependencies":[{"bom_ref":"child1-bom-ref","depends_on":[]},{"bom_ref":"parent1-bom-ref","depends_on":[]}]`)
			},
		},
		{
			name: "SBOM with relationships and packages",
			presenter: Presenter{
				document: models.Document{
					StartTimestamp: time.Now().Local().Round(0).Format(time.RFC3339),
				},
				sbom: &sbom.SBOM{
					Artifacts: sbom.Artifacts{
						Packages: syftPkg.NewCollection(
							toPkg(":child1@2.14.1", "", "child1-bom-ref"),
							toPkg(":parent1@1.18", "", "parent1-bom-ref"),
						),
					},
					Relationships: []artifact.Relationship{
						{
							Type: "dependency-of",
							From: toPkg(":child1@2.14.1", "", "child1-bom-ref"),
							To:   toPkg(":parent1@1.18", "", "parent1-bom-ref"),
						},
					},
				},
				pretty: false,
			},
			wantErr: false,
			outputCheck: func(t *testing.T, output string) {
				if !strings.Contains(output, `"dependencies":[{"bom_ref":"parent1-bom-ref","depends_on":["child1-bom-ref"]},{"bom_ref":"child1-bom-ref","depends_on":[]}]`) &&
					!strings.Contains(output, `"dependencies":[{"bom_ref":"child1-bom-ref","depends_on":[]},{"bom_ref":"parent1-bom-ref","depends_on":["child1-bom-ref"]}]`) {
					assert.Failf(t, "output - %s does not contain either of expected data", output)
				}
			},
		},
		{
			name: "SBOM with relationships and duplicate packages - scenario 1",
			presenter: Presenter{
				document: models.Document{
					StartTimestamp: time.Now().Local().Round(0).Format(time.RFC3339),
				},
				sbom: &sbom.SBOM{
					Artifacts: sbom.Artifacts{
						// Child packages are duplicate
						Packages: syftPkg.NewCollection(
							toPkg(":child1@2.14.1", "pkg:generic/child1@2.14.1?package_id=1", "child11-bom-ref"),
							toPkg(":child1@2.14.1", "pkg:generic/child1@2.14.1?package_id=2", "child12-bom-ref"),
							toPkg(":parent1@1.18", "pkg:generic/parent1@1.18", "parent1-bom-ref"),
							toPkg(":parent2@5.0", "pkg:generic/parent2@5.0", "parent2-bom-ref"),
						),
					},
					Relationships: []artifact.Relationship{
						{
							Type: "dependency-of",
							From: toPkg(":child1@2.14.1", "pkg:generic/child1@2.14.1?package_id=1", "child11-bom-ref"),
							To:   toPkg(":parent1@1.18", "pkg:generic/parent1@1.18", "parent1-bom-ref"),
						},
						{
							Type: "dependency-of",
							From: toPkg(":child1@2.14.1", "pkg:generic/child1@2.14.1?package_id=2", "child12-bom-ref"),
							To:   toPkg(":parent2@5.0", "pkg:generic/parent2@5.0", "parent2-bom-ref"),
						},
					},
				},
				pretty: false,
			},
			wantErr: false,
			outputCheck: func(t *testing.T, output string) {
				if !strings.Contains(output, `"dependencies":[{"bom_ref":"parent1-bom-ref","depends_on":["child11-bom-ref"]},{"bom_ref":"parent2-bom-ref","depends_on":["child11-bom-ref"]},{"bom_ref":"child11-bom-ref","depends_on":[]}]`) &&
					!strings.Contains(output, `"dependencies":[{"bom_ref":"parent2-bom-ref","depends_on":["child11-bom-ref"]},{"bom_ref":"child11-bom-ref","depends_on":[]},{"bom_ref":"parent1-bom-ref","depends_on":["child11-bom-ref"]}]`) {
					assert.Failf(t, "output - %s does not contain either of expected data", output)
				}
			},
		},
		{
			name: "SBOM with relationships and duplicate packages - scenario 2",
			presenter: Presenter{
				document: models.Document{
					StartTimestamp: time.Now().Local().Round(0).Format(time.RFC3339),
				},
				sbom: &sbom.SBOM{
					Artifacts: sbom.Artifacts{
						// Parent packages are duplicate
						Packages: syftPkg.NewCollection(
							toPkg(":child1@2.14.1", "pkg:generic/child1@2.14.1?package_id=1", "child1-bom-ref"),
							toPkg(":parent1@1.18", "pkg:generic/parent1@1.18?package_id=1", "parent11-bom-ref"),
							toPkg(":parent1@1.18", "pkg:generic/parent1@1.18?package_id=2", "parent12-bom-ref"),
						),
					},
					Relationships: []artifact.Relationship{
						{
							Type: "dependency-of",
							From: toPkg(":child1@2.14.1", "pkg:generic/child1@2.14.1?package_id=1", "child1-bom-ref"),
							To:   toPkg(":parent1@1.18", "pkg:generic/parent1@1.18?package_id=1", "parent11-bom-ref"),
						},
						{
							Type: "dependency-of",
							From: toPkg(":child1@2.14.1", "pkg:generic/child1@2.14.1?package_id=1", "child1-bom-ref"),
							To:   toPkg(":parent1@1.18", "pkg:generic/parent1@1.18?package_id=2", "parent12-bom-ref"),
						},
					},
				},
				pretty: false,
			},
			wantErr: false,
			outputCheck: func(t *testing.T, output string) {
				if !strings.Contains(output, `"dependencies":[{"bom_ref":"child1-bom-ref","depends_on":[]},{"bom_ref":"parent11-bom-ref","depends_on":["child1-bom-ref"]}]`) &&
					!strings.Contains(output, `"dependencies":[{"bom_ref":"parent11-bom-ref","depends_on":["child1-bom-ref"]},{"bom_ref":"child1-bom-ref","depends_on":[]}]`) {
					assert.Failf(t, "output - %s does not contain either of expected data", output)
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var output strings.Builder
			err := tc.presenter.Present(&output)

			if (err == nil) != !tc.wantErr {
				t.Fatalf("unexpected error status: %v", err)
			}

			tc.outputCheck(t, output.String())
		})
	}
}
