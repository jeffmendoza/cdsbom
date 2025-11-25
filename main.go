//
// Copyright (c) Jeff Mendoza <jlm@jlm.name>
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// SPDX-License-Identifier: MIT
//

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/reader"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"

	"github.com/jeffmendoza/cdsbom/pkg/enhance"
)

func main() {
	inFile, outFile, minScore := flags()

	document, format := read(inFile)

	if err := enhance.Do(context.Background(), document, minScore); err != nil {
		fmt.Printf("Error enhancing sbom: %v\n", err)
		os.Exit(1)
	}

	write(document, outFile, format)
	fmt.Println("Complete")
}

// flags sets up and parses flags. Return values are input file and output file
// respectively.
func flags() (string, string, int) {
	o := flag.String("out", "", "Name of output file, default is <infile>-new.json")
	s := flag.Int("min-score", 0, "The minimum effective cd score for license confidence (0-100). Default is 0.")

	flag.Usage = func() {
		fmt.Printf("Usage of %s:\n", os.Args[0])
		fmt.Printf("\tThis program takes a input SBOM and outputs an SBOM enhanced\n" +
			"\twith ClearlyDefined license information.\n")
		fmt.Printf("%s [options] <in-SBOM-file>\n", os.Args[0])
		fmt.Printf("Options:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	r := flag.Args()
	if len(r) != 1 {
		flag.Usage()
		os.Exit(1)
	}
	i := r[0]

	if *o == "" {
		if b, f := strings.CutSuffix(i, ".json"); f {
			*o = fmt.Sprintf("%s-new.json", b)
		} else {
			*o = fmt.Sprintf("%s-new", i)
		}
	}

	return i, *o, *s
}

// read reads in the sbom document and also returns the format.
func read(i string) (*sbom.Document, formats.Format) {
	reader := reader.New()
	d, err := reader.ParseFile(i)
	if err != nil {
		fmt.Printf("Error reading input SBOM: %v\n", err)
		os.Exit(1)
	}

	s := formats.Sniffer{}
	f, err := s.SniffFile(i)
	if err != nil {
		fmt.Printf("Error determining input SBOM format: %v\n", err)
		os.Exit(1)
	}
	return d, f
}

// write writes the sbom document to a file with a format
func write(s *sbom.Document, o string, f formats.Format) {
	w := writer.New(writer.WithFormat(f))
	if err := w.WriteFile(s, o); err != nil {
		fmt.Printf("Error writing outpus SBOM: %v\n", err)
		os.Exit(1)
	}
}
