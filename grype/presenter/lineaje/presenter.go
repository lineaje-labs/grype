package lineaje

import (
	"encoding/json"
	"github.com/anchore/grype/grype/presenter/models"
	"github.com/anchore/syft/syft/sbom"
	"io"
	"strings"
	"time"
)

type Presenter struct {
	document models.Document
	pretty   bool
	sbom     *sbom.SBOM
}

func NewPresenter(pb models.PresenterConfig) *Presenter {
	return &Presenter{
		document: pb.Document,
		pretty:   pb.Pretty,
		sbom:     pb.SBOM,
	}
}

func (p *Presenter) Present(output io.Writer) error {
	collectionSummary := CollectionSummary{
		StartTime:      p.document.StartTimestamp,
		Schema:         "4.0",
		CrawlerType:    "trustCenter-fastscan",
		CrawlerVersion: p.document.Descriptor.Version,
	}
	if p.sbom != nil {
		bomRefDepMap := make(map[string]*Set[string])
		allBomRefsWithParentSet := NewSet[string]()
		for _, sbomRelationship := range p.sbom.Relationships {
			if sbomRelationship.Type == "dependency-of" { // Flip the relationship
				parentBomRef := string(sbomRelationship.To.ID())
				if childBomRefList, parentBomRefFound := bomRefDepMap[parentBomRef]; parentBomRefFound {
					childBomRefList.Insert(string(sbomRelationship.From.ID()))
					bomRefDepMap[parentBomRef] = childBomRefList
				} else {
					bomRefDepMap[parentBomRef] = NewSet[string](string(sbomRelationship.From.ID()))
				}
				allBomRefsWithParentSet.Insert(string(sbomRelationship.From.ID()))
			}
		}
		if p.sbom.Artifacts.Packages != nil {
			uniquePURLsVsBomRef := make(map[string]string)
			for pkgCatalogEntry := range p.sbom.Artifacts.Packages.Enumerate() {
				pkgCatalogEntryPURL := GetPURLFromPkgCatalogEntry(pkgCatalogEntry)
				var componentIsDuplicate bool
				componentBomRef := string(pkgCatalogEntry.ID())
				duplicateError, originalBomRef := GetBomRefForDuplicatePURL(uniquePURLsVsBomRef, pkgCatalogEntryPURL)
				if duplicateError == nil {
					if len(originalBomRef) == 0 {
						uniquePURLsVsBomRef[GetPURLWithoutQualifiers(pkgCatalogEntryPURL)] = componentBomRef
						if _, found := bomRefDepMap[componentBomRef]; !found { // Add an empty dependency relationship, if not set
							bomRefDepMap[componentBomRef] = NewSet[string]()
						}
					} else { // Update dependency relationship
						componentIsDuplicate = true
						// If this duplicate component has dependencies, then delete it
						if _, found := bomRefDepMap[componentBomRef]; found {
							delete(bomRefDepMap, componentBomRef)
						}
						// If any component is pointing to this duplicate component, then update it
						for parentBomRef, childBomRefSet := range bomRefDepMap {
							for _, childBomRef := range childBomRefSet.List() {
								if childBomRef == componentBomRef {
									childBomRefSet.Remove(componentBomRef)
									childBomRefSet.Insert(originalBomRef)
									bomRefDepMap[parentBomRef] = childBomRefSet
									break
								}
							}
						}
					}
				} else {
					// In case there is an error in parsing the PURL, add an empty dependency relationship, if not set
					if _, found := bomRefDepMap[componentBomRef]; !found {
						bomRefDepMap[componentBomRef] = NewSet[string]()
					}
				}

				collectionReport := CollectionReport{
					OriginBomRef: componentBomRef,
					BomRef:       componentBomRef,
					CollectionInput: &CollectionInput{
						SrcInfo: nil,
						PkgInfo: &PkgInformation{
							Type: pkgCatalogEntry.Type.PackageURLType(),
							PURL: pkgCatalogEntryPURL,
						},
						IsTopLevelInput: "false", // Will be overwritten later
					},
					CollectionOutput: &CollectionOutput{
						BomRef:  componentBomRef,
						SrcInfo: nil,
						PkgInfo: &PkgInformation{
							Type:          pkgCatalogEntry.Type.PackageURLType(),
							ChecksumMatch: "unknown",
							PURL:          pkgCatalogEntryPURL,
							Licenses:      nil,
						},
						VulnData: models.Document{
							Matches:    nil,
							Source:     p.document.Source,
							Distro:     p.document.Distro,
							Descriptor: p.document.Descriptor,
						},
					},
					Status: FastScanReportStatus,
				}
				resourceID, _ := ConvertToResourceId(pkgCatalogEntryPURL)
				collectionReport.CollectionInput.PkgInfo.InternalResourceId = resourceID
				collectionReport.CollectionOutput.PkgInfo.InternalResourceId = resourceID
				if componentIsDuplicate {
					collectionReport.Status = DuplicateReportStatus
				}
				for _, vulnMatch := range p.document.Matches {
					if vulnMatch.Artifact.ID == componentBomRef {
						collectionReport.CollectionOutput.VulnData.Matches =
							append(collectionReport.CollectionOutput.VulnData.Matches, vulnMatch)
					}
				}
				for _, pkgLicense := range pkgCatalogEntry.Licenses.ToSlice() {
					license := License{
						Id:      pkgLicense.Value,
						Content: pkgLicense.Contents,
						Url:     strings.Join(pkgLicense.URLs, ","),
					}
					collectionReport.CollectionOutput.PkgInfo.Licenses =
						append(collectionReport.CollectionOutput.PkgInfo.Licenses, license)
				}
				for _, cpeValue := range pkgCatalogEntry.CPEs {
					collectionReport.CollectionOutput.PkgInfo.CPES =
						append(collectionReport.CollectionOutput.PkgInfo.CPES, cpeValue.Attributes.String())
				}
				// If this component does not have any parent, then it is a top level component
				if allBomRefsWithParentSet.Contains(collectionReport.BomRef) == false {
					collectionReport.CollectionInput.IsTopLevelInput = "true"
				}
				collectionSummary.CollectionReportList = append(collectionSummary.CollectionReportList, collectionReport)
			}
			collectionSummary.Dependencies = createDependencyMapForReport(bomRefDepMap)
		}
	}
	collectionSummary.EndTime = time.Now().Local().Round(0).Format(time.RFC3339)
	enc := json.NewEncoder(output)
	// prevent > and < from being escaped in the payload
	enc.SetEscapeHTML(false)
	if p.pretty {
		enc.SetIndent("", " ")
	}
	return enc.Encode(&collectionSummary)
}

func createDependencyMapForReport(bomRefDepMap map[string]*Set[string]) []ComponentRelationship {
	var dependencies []ComponentRelationship
	if bomRefDepMap == nil {
		return dependencies
	}
	for parentBomRef, childBomRefList := range bomRefDepMap {
		children := childBomRefList
		if children == nil {
			children = NewSet[string]()
		}
		dependency := ComponentRelationship{
			BomRef:    parentBomRef,
			DependsOn: *children,
		}
		dependencies = append(dependencies, dependency)
	}
	return dependencies
}
