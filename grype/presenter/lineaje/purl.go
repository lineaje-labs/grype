package lineaje

import (
	"fmt"
	"github.com/anchore/packageurl-go"
    "github.com/anchore/syft/syft/pkg"
	"math/rand"
	"strings"
	"time"

)

var (
	UnresolvedId = "unresolved-" // This keyword indicates any resource id which was unresolved
)

// resourceIDReplacer is used to replace special characters in a resource id to support data transformation scripts
var resourceIDReplacer = strings.NewReplacer(
	"@", ":", // Replace "@" in a resource id with colon
	"/", ":", // Replace linux path separator in a resource id with colon
	"\\", "__", // Replace windows path separator in a resource id with underscores
	" ", "__", // Replace space in a resource id with underscores
)

// ConvertToResourceId converts a traditional PURL to a Resource ID string and also returns the PURL Object
func ConvertToResourceId(purlValue string) (string, error) {
	s1 := rand.NewSource(time.Now().UnixNano())
	r1 := rand.New(s1)
	if len(purlValue) == 0 {
		return fmt.Sprintf(UnresolvedId+"%d", r1.Int63()), fmt.Errorf("purl is empty")
	}
	purlInstance, err := packageurl.FromString(purlValue)
	if err != nil {
		return fmt.Sprintf(UnresolvedId+"%d", r1.Int63()), fmt.Errorf(
			"purl %s could not be parsed due to - %v", purlValue, err)
	}
	var resourceID string
	if len(purlInstance.Namespace) > 0 {
		if len(resourceID) > 0 {
			resourceID += ":" + purlInstance.Namespace
		} else {
			resourceID = purlInstance.Namespace
		}
	} else if len(resourceID) == 0 { // Prevent conflicts with similar package names by adding type as a differentiator
		resourceID = purlInstance.Type
	}
	if len(purlInstance.Name) > 0 {
		if len(resourceID) > 0 {
			resourceID += ":" + purlInstance.Name
		} else {
			resourceID = purlInstance.Name
		}
	}
	if len(purlInstance.Version) > 0 {
		resourceID += ":" + purlInstance.Version
	}
	// Data transformation cannot handle "/" in resource id
	return resourceIDReplacer.Replace(resourceID), nil
}

func GetPURLWithoutQualifiers(purlValue string) string {
	purlInstance, err := packageurl.FromString(purlValue)
	if err != nil {
		return ""
	}
	purlInstance.Qualifiers = nil
	return purlInstance.String()
}

// GetBomRefForDuplicatePURL retrieves the BOM reference for a given PURL after normalizing its qualifiers.
// Returns an error if the PURL is empty or invalid, and the BOM reference if found in the provided map.
func GetBomRefForDuplicatePURL(purlsVsBomRef map[string]string, purlValue string) (error, string) {
	if len(purlValue) == 0 {
		return fmt.Errorf("purl is empty"), ""
	}
	purlInstance, err := packageurl.FromString(purlValue)
	if err != nil {
		return fmt.Errorf("purl %s could not be parsed due to - %v", purlValue, err), ""
	}
	purlInstance.Qualifiers = nil
	updatedPurlValue := purlInstance.String()
	if bomRef, purlFound := purlsVsBomRef[updatedPurlValue]; purlFound {
		return nil, bomRef
	} else {
		return nil, ""
	}
}

func GetPURLFromPkgCatalogEntry(pkgCatalogEntry pkg.Package) string {
	if len(pkgCatalogEntry.PURL) > 0 {
		return pkgCatalogEntry.PURL
    } else {
		purlInstance := packageurl.NewPackageURL("generic", "", pkgCatalogEntry.Name, pkgCatalogEntry.Version, nil, "")
		return purlInstance.ToString()
    }
}
