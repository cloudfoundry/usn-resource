package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"

	"github.com/cloudfoundry/usn-resource/api"
)

func main() {
	var request api.Request
	err := json.NewDecoder(os.Stdin).Decode(&request)

	if err != nil {
		log.Fatal("check: bad stdin: parse error", err)
	}
	rawData, err := api.GetOvalRawData(request.Source.OS)
	if err != nil {
		log.Fatalf("check: error retreiving oval data: '%s'", err)
	}
	ovalDefinitions, err := api.ParseOvalData(rawData)
	if err != nil {
		log.Fatalf("check: error parsing oval data: '%s'", err)
	}

	fmt.Fprintf(os.Stderr, "Oval data generated at %s\n", ovalDefinitions.Timestamp)

	versions, _ := GetLatestVersions(ovalDefinitions, request.Version, request.Source.Priorities) //nolint:errcheck
	if len(versions) == 0 && request.Version.GUID == "" {
		versions = append(versions, api.Version{GUID: "bootstrap"})
	}
	err = json.NewEncoder(os.Stdout).Encode(&versions)
	if err != nil {
		log.Fatal("check: bad stdout: encode error", err)
	}
}

func GetLatestVersions(definitions api.OvalDefinitions, version api.Version, priorities []string) ([]api.Version, error) {
	var versions []api.Version
	for i := len(definitions.Definitions) - 1; i >= 0; i-- {
		def := definitions.Definitions[i]

		if strings.Contains(def.Metadata.GetUSNUrl(), "LSN") {
			continue
		}

		cvePriorities := getCVEPriorities(def)
		if anyEqual(cvePriorities, priorities) {
			versions = append(versions, api.Version{GUID: def.Metadata.GetUSNUrl()})
		}

		if def.Metadata.GetUSNUrl() == version.GUID {
			break
		}
	}
	slices.Reverse(versions)
	return versions, nil
}

func getCVEPriorities(definition api.Definition) []string {
	priorities := []string{}
	for _, cve := range definition.Metadata.Advisory.CVEs {
		priorities = append(priorities, cve.Priority)
	}
	return priorities
}

func anyEqual(a []string, s []string) bool {
	m := map[string]struct{}{}
	for _, v := range s {
		m[v] = struct{}{}
	}
	for _, v := range a {
		if _, ok := m[v]; ok {
			return true
		}
	}
	return false
}
