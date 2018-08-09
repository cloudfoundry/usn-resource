package main

import (
	"encoding/json"
	"io/ioutil"
	"os"
	"path/filepath"

	"log"

	"github.com/cloudfoundry/usn-resource/api"
)

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

type Response struct {
	Version  Version                `json:"version"`
	Metadata map[string]interface{} `json:"metadata"`
}

func main() {
	path := os.Args[1]
	os.MkdirAll(path, 0755)

	var request InRequest

	err := json.NewDecoder(os.Stdin).Decode(&request)
	if err != nil {
		log.Fatal("in: bad stdin: parse error", err)
	}

	response := Response{Version: request.Version}
	usn := api.USNFromURL(request.Version.GUID)
	response.Metadata = map[string]interface{}{}
	response.Metadata["title"] = usn.Title()
	response.Metadata["description"] = usn.Description()
	response.Metadata["date"] = usn.Date()
	response.Metadata["releases"] = uniq(usn.Releases())
	response.Metadata["priorities"] = uniq(usn.CVEs().Priorities())
	ioutil.WriteFile(filepath.Join(path, "usn.md"), []byte(usn.Markdown()), 0644)

	err = json.NewEncoder(os.Stdout).Encode(&response)
	if err != nil {
		log.Fatal("in: bad stdout: encode error", err)
	}
}

func uniq(a []string) []string {
	r := []string{}
	m := map[string]struct{}{}
	for _, v := range a {
		if _, ok := m[v]; !ok {
			m[v] = struct{}{}
			r = append(r, v)
		}
	}
	return r
}
