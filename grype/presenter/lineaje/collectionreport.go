package lineaje

import "github.com/anchore/grype/grype/presenter/models"

type SrcInformation struct {
	RepoURL string `json:"srcurl,omitempty"`
	Tag string `json:"tag,omitempty"` // Ref tag of the source repo that should be used
	PURL string `json:"purl,omitempty"` // PURL of the Repo Source
}

type Contact struct {
	Name  string `json:"name,omitempty"`
	Email string `json:"email,omitempty"`
	Phone string `json:"phone,omitempty"`
}

type Supplier struct {
	Name     string    `json:"name,omitempty"`
	Url      []string  `json:"url,omitempty"`
	Contacts []Contact `json:"contacts,omitempty"`
}

type License struct {
	Id          string `json:"id"`
	ContentType string `json:"contentType,omitempty"`
	Encoding    string `json:"encoding,omitempty"`
	Content     string `json:"content,omitempty"`
	Url         string `json:"url,omitempty"`
}

type PkgInformation struct {
	InternalResourceId string `json:"resourceid,omitempty"` // Used only while saving data in the Collection Summary JSON
	Type string `json:"type,omitempty"`
	ChecksumMatch string `json:"checksummatch,omitempty"`
	PURL          string `json:"purl,omitempty"` // Ref - https://github.com/package-url/purl-spec
	CPES []string `json:"cpes,omitempty"` // Ref - https://nvd.nist.gov/products/cpe
	Supplier      *Supplier `json:"supplier,omitempty"`
	Licenses      []License `json:"licenses,omitempty"`
	LicenseString string    `json:"license_string,omitempty"`
}

// CollectionInput is the input artifact detail on which the task collection is executed.
type CollectionInput struct {
	SrcInfo *SrcInformation `json:"srcInfo,omitempty"`
	PkgInfo *PkgInformation `json:"pkgInfo,omitempty"`
	IsTopLevelInput string `json:"is_top_level_input"` // Indicates if this was a direct input or a dependency input. Used to build the collection summary dep tree
}

// CollectionOutput is the output artifact details after the task collection is completed. It should be more enriched.
type CollectionOutput struct {
	BomRef   string          `json:"bom_ref,omitempty"`
	SrcInfo  *SrcInformation `json:"srcInfo,omitempty"`
	PkgInfo  *PkgInformation `json:"pkgInfo,omitempty"`
	VulnData models.Document `json:"vuln_data,omitempty"`
}

type CollectionReportStatus string

const (
	DuplicateReportStatus CollectionReportStatus = "duplicate" // Set when input for collection is a duplicate of another input
	InvalidReportStatus   CollectionReportStatus = "invalid"   // Set when input was ignored due to it not being invalid
	FastScanReportStatus  CollectionReportStatus = "fast-scan" // Set when the component was processed using Fast Scan
)

// CollectionReport contains the status, input and output for a particular collection run for a specific artifact.
type CollectionReport struct {
	OriginBomRef string `json:"origin_bom_ref,omitempty"` // Optional reference that ties back to the original SBOM that it was converted from
	BomRef       string `json:"bom_ref,omitempty"`
	CollectionInput  *CollectionInput       `json:"input,omitempty"`
	CollectionOutput *CollectionOutput      `json:"output,omitempty"`
	Status           CollectionReportStatus `json:"status,omitempty"`
}

// ComponentRelationship specifies the dependency relationship between various components based on their BomRef
type ComponentRelationship struct {
	BomRef    string      `json:"bom_ref"`
	DependsOn Set[string] `json:"depends_on"`
}

type CollectionSummary struct {
	StartTime string `json:"starttime,omitempty"`
	EndTime   string `json:"endtime,omitempty"`
	Schema    string `json:"schema_no,omitempty"`
	CrawlerType    string `json:"crawlertype,omitempty"`
	CrawlerVersion string `json:"crawlerversion,omitempty"`
	CollectionReportList []CollectionReport `json:"collectionreport"`
	Dependencies []ComponentRelationship `json:"dependencies"`
}
