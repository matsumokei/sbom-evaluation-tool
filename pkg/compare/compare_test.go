package compare_test

import (
	"fmt"
	"testing"

	"github.com/matsumokei/sbom-evaluation-tool/pkg/compare"
)


func TestMatch(t *testing.T) {
	tests := []struct{
		name string
		pkgs []compare.PackageBasicData
		tgts []compare.PackageBasicData
		expected bool
	}{
		{
			name: "match",
			pkgs: []compare.PackageBasicData{
				Name:     "github.com/bmatcuk/doublestar",
				Version: "v1.3.1",
				//Licenses: pkg.Licenses,
				PURL: "pkg:golang/github.com/bmatcuk/doublestar@v1.3.1",
			},
			tgts: []compare.PackageBasicData{
				Name:     "github.com/bmatcuk/doublestar",
				Version: "v1.3.1",
				//Licenses: pkg.Licenses,
				PURL: "pkg:golang/github.com/bmatcuk/doublestar@v1.3.1",
			},
			expected: true,
		},
		{
			name: "unmatch",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func (t *testing.T) {
			if tt.expected != (tt.pkgs) {
				t.Fatalf("input:%v  value:%v  judge: false\n\n", tt.input, (tt.input))
			}else{
				fmt.Printf("input:%v value:%v judge: ok\n\n", tt.input, (tt.input))
			}
		})
	}
}