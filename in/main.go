package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cloudfoundry/usn-resource/api"
)

type MetadataField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Response struct {
	Version  api.Version     `json:"version"`
	Metadata []MetadataField `json:"metadata"`
}

func main() {
	path := os.Args[1]
	err := os.MkdirAll(path, 0755)
	if err != nil {
		log.Fatal("in: making directory", err)
	}

	var request api.Request

	err = json.NewDecoder(os.Stdin).Decode(&request)
	if err != nil {
		log.Fatal("in: bad stdin: parse error", err)
	}

	response := Response{Version: request.Version}

	if request.Version.GUID == "bootstrap" {
		err = os.WriteFile(filepath.Join(path, "usn.json"), []byte("{}"), 0644)
		if err != nil {
			log.Fatal("in: writing to usn.json bootstrap", err)
		}

		err = json.NewEncoder(os.Stdout).Encode(&response)
		if err != nil {
			log.Fatal("in: bad stdout: encode error", err)
		}
		return
	}

	rawData, err := api.GetOvalRawData(request.Source.OS)
	if err != nil {
		log.Fatalf("in: error retreiving oval data: '%s'", err)
	}
	ovalDefinitions, err := api.ParseOvalData(rawData)
	if err != nil {
		log.Fatalf("in: error parsing oval data: '%s'", err)
	}

	fmt.Fprintf(os.Stderr, "Oval data generated at %s\n", ovalDefinitions.Timestamp)

	def, err := ovalDefinitions.GetDefinition(request.Version.GUID)
	if err != nil {
		log.Fatalf("in: error retreiving USN: '%s'", err)
	}
	usnMetadata := def.ToUSNMetadata(request.Source.OS)
	response.Metadata = []MetadataField{
		{"title", usnMetadata.Title},
		{"url", usnMetadata.URL},
		{"description", usnMetadata.Description},
		{"date", usnMetadata.Date},
		{"releases", strings.Join(usnMetadata.Releases, ", ")},
		{"priorities", strings.Join(usnMetadata.Priorities, ", ")},
		{"severities", strings.Join(usnMetadata.Severities, ", ")},
		{"cves", strings.Join(usnMetadata.CVEs, ", ")},
	}
	f, err := os.Create(filepath.Join(path, "usn.json"))
	if err != nil {
		log.Fatal("in: opening usn.json", err)
	}
	err = json.NewEncoder(f).Encode(&usnMetadata)
	if err != nil {
		log.Fatal("in: encoding usn.json", err)
	}

	err = json.NewEncoder(os.Stdout).Encode(&response)
	if err != nil {
		log.Fatal("in: bad stdout: encode error", err)
	}
}
