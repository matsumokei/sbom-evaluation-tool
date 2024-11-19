/*
Copyright © 2024 NAME HERE <EMAIL ADDRESS>
*/
package cmd

import (
	"fmt"
	"log"

	"github.com/matsumokei/sbom-evaluation-tool/pkg/compare"
	"github.com/spf13/cobra"
)

var file1, file2 string

// compareCmd represents the compare command
var compareCmd = &cobra.Command{
	Use:   "compare [flags] { - | FILE...}",
	//Args:  cobra.MinimumNArgs(2),
	Short: "A brief description of your command",
	Long: `A longer description that spans multiple lines and likely contains examples
and usage of using your command. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("compare called")
		runCompare()
		},
}

func init() {
	rootCmd.AddCommand(compareCmd)

	//フラグの値を変数にバインド
	compareCmd.Flags().StringVar(&file1, "file1", "f1", "First input SBOM for comparing")
	compareCmd.Flags().StringVar(&file2, "file2", "f2", "Second input SBOM for comparing")

	//必須のフラグに指定
	compareCmd.MarkFlagRequired("file1")
	compareCmd.MarkFlagRequired("file2")

	// Here you will define your flags and configuration settings.

	// Cobra supports Persistent Flags which will work for this command
	// and all subcommands, e.g.:
	// compareCmd.PersistentFlags().String("foo", "", "A help for foo")

	// Cobra supports local flags which will only run when this command
	// is called directly, e.g.:
	// compareCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
}

func runCompare() {
	pkgs, err := compare.BomParser(file1)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("- Components: %d\n", len(pkgs))
	//fmt.Print(pkgs)

	tgts, err := compare.BomParser(file2)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("- Components: %d\n", len(tgts))

	//差分を取る
	matches, unmatches, onlytgets := compare.Match(pkgs, tgts)
	// fmt.Print(matches)
	// fmt.Print(unmatches)

	// matchesCsv := csvDecode(matches)
	// csvWrite(matchesCsv, "both.csv")

	// unmatchesCsv := csvDecode(unmatches)
	// csvWrite(unmatchesCsv, "src.csv")

	// onlytgetsCsv := csvDecode(onlytgets)
	// csvWrite(onlytgetsCsv, "tgt.csv")

	fmt.Printf("both: %s, syft:%s, trivy:%s", len(matches), len(unmatches), len(onlytgets))
}
