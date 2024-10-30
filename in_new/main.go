package in_new

import (
	"encoding/json"
	"github.com/cloudfoundry/usn-resource/api"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Todo Deduplicate these structs
type Source struct {
	OS         string   `json:"os"`
	Priorities []string `json:"priorities"`
}
type Version struct {
	GUID string `json:"guid"`
}

type InRequest struct {
	Source  Source  `json:"source"`
	Version Version `json:"version"`
}

type MetadataField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Response struct {
	Version  Version         `json:"version"`
	Metadata []MetadataField `json:"metadata"`
}

func main() {
	path := os.Args[1]
	err := os.MkdirAll(path, 0755)
	if err != nil {
		log.Fatal("in: making directory", err)
	}

	var request InRequest

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
