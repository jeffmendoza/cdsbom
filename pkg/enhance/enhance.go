//
// Copyright (c) Jeff Mendoza <jlm@jlm.name>
// Copyright (c) Gary O'Neall <gary@sourceauditor.com>
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
// SPDX-License-Identifier: MIT
//

// Package enhance enhances sbom documents with ClearlyDefined license
// information
package enhance

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/guacsec/sw-id-core/coordinates"
	"github.com/hashicorp/go-retryablehttp"
	"github.com/protobom/protobom/pkg/sbom"
	"golang.org/x/time/rate"

	"github.com/jeffmendoza/cdsbom/pkg/cd"
)

var HTTPClient *retryablehttp.Client
var Transport http.RoundTripper

func init() {
	Transport = &transport{
		Wrapped: http.DefaultTransport,
		RL:      rate.NewLimiter(rate.Every(time.Minute), 250),
	}
	HTTPClient = retryablehttp.NewClient()
	HTTPClient.HTTPClient.Transport = Transport
}

// Do modifies the License and LicenseConcluded fields of the Nodes in the
// provided protobom Document with results from ClearlyDefined Warnings and
// updates are printed to stdout. TODO: Update to use a provided io.Writer or
// logger, also to use provided http client/transport and context.
func Do(ctx context.Context, s *sbom.Document, minScore int) error {
	coords := CoordList(s)
	defs, err := getDefs(ctx, coords)
	if err != nil {
		return err
	}
	updateLicenses(s, defs, minScore)
	return nil
}

// CoordList takes an SBOM document and returns a slice of all ClearlyDefined
// Coordinates found in that document.
func CoordList(s *sbom.Document) []string {
	nodes := s.GetNodeList().GetNodes()
	coords := make(map[string]bool)
	for _, node := range nodes {
		if p := node.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]; p != "" {
			if c, err := coordinates.ConvertPurlToCoordinate(p); err == nil {
				coords[c.ToString()] = true
			} else {
				fmt.Printf("Coordinate conversion not supported for: %q\n", p)
			}
		}
	}
	return slices.Collect(maps.Keys(coords))
}

func getDefs(ctx context.Context, coords []string) (map[string]*cd.Definition, error) {
	allDefs := make(map[string]*cd.Definition, len(coords))
	chunkSize := 500
	for i := 0; i < len(coords); i += chunkSize {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := i + chunkSize
		if end > len(coords) {
			end = len(coords)
		}
		defs, err := getDefsFromService(ctx, coords[i:end])
		if err != nil {
			return nil, err
		}
		maps.Copy(allDefs, defs)
	}
	return allDefs, nil
}

func getDefsFromService(ctx context.Context, coords []string) (map[string]*cd.Definition, error) {
	cs, err := json.Marshal(coords)
	if err != nil {
		return nil, fmt.Errorf("error marshalling coordinates: %w", err)
	}
	req, err := retryablehttp.NewRequestWithContext(ctx, "POST", "https://api.clearlydefined.io/definitions", bytes.NewBuffer(cs))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	rsp, err := HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error querying ClearlyDefined: %w", err)
	}
	if rsp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("error querying ClearlyDefined: %v", rsp.Status)
	}
	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response body: %w", err)
	}
	var defs map[string]*cd.Definition
	if err := json.Unmarshal(body, &defs); err != nil {
		return nil, fmt.Errorf("error unmarshalling JSON: %w", err)
	}
	return defs, nil
}

func updateLicenses(s *sbom.Document, defs map[string]*cd.Definition, minScore int) {
	for _, node := range s.GetNodeList().GetNodes() {
		updateNode(node, defs, minScore)
	}
}

func updateNode(n *sbom.Node, defs map[string]*cd.Definition, minScore int) {
	p := n.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]
	if p == "" {
		return
	}
	c, err := coordinates.ConvertPurlToCoordinate(p)
	if err != nil {
		return
	}
	d, ok := defs[c.ToString()]
	if !ok {
		return
	}
	if len(d.Described.Tools) == 0 {
		return
	}
	old := strings.Join(n.GetLicenses(), " AND ")
	new := d.Licensed.Declared
	if old != new && d.Scores.Effective >= minScore {
		fmt.Printf("Update Declared License\n")
		fmt.Printf("Name: %v\tVersion: %v\n", n.GetName(), n.GetVersion())
		fmt.Printf("\t\t\t\tSBOM License: %q\tCD License: %q\n", old, new)
		n.Licenses = []string{new}
	}

	oldDisc := n.GetLicenseConcluded()
	newDisc := strings.Join(d.Licensed.Facets.Core.Discovered.Expressions, " AND ")
	if oldDisc != newDisc && d.Scores.Effective >= minScore {
		fmt.Printf("Update Discovered License\n")
		fmt.Printf("Name: %v\tVersion: %v\n", n.GetName(), n.GetVersion())
		fmt.Printf("\t\t\t\tSBOM License: %q\tCD License: %q\n", oldDisc, newDisc)
		n.LicenseConcluded = newDisc
	}
}
