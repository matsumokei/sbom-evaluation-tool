package compare

import (
	_"encoding/csv"
	"log"
	"os"

	cdx "github.com/CycloneDX/cyclonedx-go"
)

type Package struct {
	PackageBasicData
	PackageCustomData
}

// PackageBasicData contains non-ambiguous values (type-wise) from pkg.Package.
type PackageBasicData struct {
	//ID        string          `json:"id"`
	Name    string `json:"name"`
	Version string `json:"version"`
	//Type      pkg.Type        `json:"type"`
	//FoundBy   string          `json:"foundBy"`
	//Locations []file.Location `json:"locations"`
	//Licenses  licenses        `json:"licenses"`
	//Language  pkg.Language    `json:"language"`
	//CPEs      cpes            `json:"cpes"`
	PURL string `json:"purl"`
}

// PackageCustomData contains ambiguous values (type-wise) from pkg.Package.
type PackageCustomData struct {
	MetadataType string `json:"metadataType,omitempty"`
	Metadata     any    `json:"metadata,omitempty"`
}


// func csvWrite(d [][]string, path string) error {
// 	f, err := os.Create(path)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer f.Close()
// 	w := csv.NewWriter(f)
// 	if err := w.Error(); err != nil {
// 		log.Fatalln("error writing csv:", err)
// 	}
// 	w.WriteAll(d) // 一度にすべて書き込む

// 	return nil
// }

func BomParser(path string) ([]PackageBasicData, error) {
	//Open bom file
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	// Decode the BOM
	bom := new(cdx.BOM)
	decoder := cdx.NewBOMDecoder(f, cdx.BOMFileFormatJSON)
	if err = decoder.Decode(bom); err != nil {
		panic(err)
	}

	artifacts := make([]PackageBasicData, 0)
	//Convert -> SBOM standard model
	for _, cmp := range *bom.Components {
		//fmt.Printf("Name: %s\n", cmp.Name)
		pkg := PackageBasicData{
			Name:    cmp.Name,
			Version: cmp.Version,
			//Licenses: pkg.Licenses,
			PURL: cmp.PackageURL,
		}
		artifacts = append(artifacts, pkg)
	}
	return artifacts, nil

}

// func CSVDecode(pkgs []PackageBasicData) [][]string {

// 	numRows := len(pkgs)
// 	d := make([][]string, numRows+1)

// 	// Add header row
// 	d[0] = []string{"name", "version", "purl"}

// 	// Add data rows
// 	for i := 0; i < numRows; i++ {
// 		d[i+1] = []string{pkgs[i].Name,
// 			pkgs[i].Version,
// 			pkgs[i].PURL,
// 			// strconv.FormatFloat(d.col1[i], 'f', -1, 64),
// 			// strconv.FormatFloat(d.col2[i], 'f', -1, 64),
// 		}
// 	}

// 	return d
// }

// type Attribute interface{
// 	diff
// }

func Match(pkgs, tgts []PackageBasicData) ([]PackageBasicData, []PackageBasicData, []PackageBasicData) {
	matches := make([]PackageBasicData, 0)   //both
	unmatches := make([]PackageBasicData, 0) //onlysrcs
	onlytgts := make([]PackageBasicData, 0)  //onlytgets
	for _, p := range pkgs {
		hit := false
		for _, t := range tgts {
			if p.diffAttr(t) {
				matches = append(matches, p) //src and tgt
				hit = true
				break
			}
		}
		if hit == false {
			unmatches = append(unmatches, p) //src and not tgt
		}
	}

	for _, t := range tgts {
		hit := false
		for _, m := range matches {
			if t.diffAttr(m) {
				hit = true
				break
			}
		}
		if hit == false {
			onlytgts = append(onlytgts, t)
		}
	}
	return matches, unmatches, onlytgts
}

func (p PackageBasicData) diffAttr(t PackageBasicData) bool {
	return matchAttr(p.Name, t.Name) && matchAttr(p.Version, t.Version)
}

func matchAttr(src string, tgt string) bool {
	switch {
	case src == tgt:
		return true //Equal, Subset, Superset
	case src != tgt:
		return false //
	default:
		return false
	}
}
