package check_new

import (
	"encoding/json"
	"github.com/cloudfoundry/usn-resource/api"
	"log"
	"os"
	"slices"
)

type Source struct {
	OS         string   `json:"os"`
	Priorities []string `json:"priorities"`
}

type Version struct {
	GUID string `json:"guid"`
}

type CheckRequest struct {
	Source  Source  `json:"source"`
	Version Version `json:"version"`
}

func main() {
	var request CheckRequest
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

	versions, err := GetLatestVersions(ovalDefinitions, request.Version, request.Source.Priorities)
	if len(versions) == 0 && request.Version.GUID == "" {
		versions = append(versions, Version{GUID: "bootstrap"})
	}
	err = json.NewEncoder(os.Stdout).Encode(&versions)
	if err != nil {
		log.Fatal("check: bad stdout: encode error", err)
	}
}

func GetLatestVersions(definitions api.OvalDefinitions, version Version, priorities []string) ([]Version, error) {
	var versions []Version
	for i := len(definitions.Definitions) - 1; i >= 0; i-- {
		def := definitions.Definitions[i]
		if def.Id == version.GUID {
			break
		}
		cvePriorities := getCVEPriorities(def)
		if anyEqual(cvePriorities, priorities) {
			versions = append(versions, Version{GUID: def.Id})
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
