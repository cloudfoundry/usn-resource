package main

import (
	"encoding/json"
	"github.com/mmcdole/gofeed"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

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

type MetadataField struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type USNMetadata struct {
	URL         string   `json:"url"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Date        string   `json:"date"`
	Releases    []string `json:"releases"`
	Priorities  []string `json:"priorities"`
	CVEs        []string `json:"cves"`
}

type Response struct {
	Version  Version         `json:"version"`
	Metadata []MetadataField `json:"metadata"`
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

	if request.Version.GUID == "bootstrap" {
		ioutil.WriteFile(filepath.Join(path, "usn.json"), []byte("{}"), 0644)
		err = json.NewEncoder(os.Stdout).Encode(&response)
		if err != nil {
			log.Fatal("in: bad stdout: encode error", err)
		}
		return
	}

	usn := getUSN(request.Version.GUID)
	cveURLs := []string{}
	for _, cve := range usn.CVEs() {
		cveURLs = append(cveURLs, cve.URL)
	}

	response.Metadata = []MetadataField{
		{"title", usn.Title()},
		{"url", request.Version.GUID},
		{"description", usn.Description()},
		{"date", usn.Date()},
		{"releases", strings.Join(uniq(usn.Releases()), ", ")},
		{"priorities", strings.Join(uniq(usn.CVEs().Priorities()), ", ")},
		{"cves", strings.Join(cveURLs, ", ")},
	}
	usnMetadata := USNMetadata{
		Title:       usn.Title(),
		URL:         request.Version.GUID,
		Description: usn.Description(),
		Date:        usn.Date(),
		Releases:    uniq(usn.Releases()),
		Priorities:  uniq(usn.CVEs().Priorities()),
		CVEs:        cveURLs,
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

func getUSN(guid string) (*api.USN) {
	fp := gofeed.NewParser()
	feed, _ := fp.ParseURL("https://usn.ubuntu.com/usn/rss.xml")

	for _, item := range feed.Items {
		if guid == item.GUID {
			return api.USNFromFeed(item)

		}
	}

	log.Fatal("in: USN not found on rss feed, usn guid: ", guid)
	return &api.USN{}
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
