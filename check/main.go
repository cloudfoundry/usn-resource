package main

import (
	"encoding/json"
	"log"
	"os"

	"github.com/cloudfoundry/usn-resource/api"
	"github.com/mmcdole/gofeed"
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

	feed, err := gofeed.NewParser().ParseURL(api.FeedURL)
	if err != nil {
		log.Fatalf("check: error parsing feed: '%s' - %v", api.FeedURL, err)
	}

	var response []Version
	for _, item := range feed.Items {
		// if we found the current version on the feed, bail out from the loop
		if request.Version.GUID == item.GUID {
			break
		}

		usn := api.USNFromFeed(item)
		if !usn.IsForRelease(request.Source.OS) {
			continue
		}
		priorities := usn.CVEs().Priorities()
		if !anyEqual(priorities, request.Source.Priorities) {
			continue
		}
		response = append(response, Version{GUID: item.GUID})
	}
	if len(response) == 0 && request.Version.GUID == "" {
		response = append(response, Version{GUID: "bootstrap"})
	}

	err = json.NewEncoder(os.Stdout).Encode(&response)
	if err != nil {
		log.Fatal("check: bad stdout: encode error", err)
	}
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
