package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"

	"log"

	"github.com/PuerkitoBio/goquery"
	"github.com/mmcdole/gofeed"
	yaml "gopkg.in/yaml.v2"
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

	fp := gofeed.NewParser()
	feed, _ := fp.ParseURL("https://usn.ubuntu.com/usn/rss.xml")
	response := []Version{}
	for _, item := range feed.Items {
		markdown := getMarkdown(usnID(item.GUID))
		releases := releaseNames(markdown)
		if !contains(releases, request.Source.OS) {
			continue
		}
		priorities := cvePriorities(cveLinks(markdown))
		if !any(priorities, request.Source.Priorities) {
			continue
		}
		response = append(response, Version{GUID: item.GUID})
		if request.Version.GUID == item.GUID {
			break
		}
	}

	err = json.NewEncoder(os.Stdout).Encode(&response)
	if err != nil {
		log.Fatal("check: bad stdout: encode error", err)
	}
}

func usnID(address string) string {
	u, err := url.Parse(address)
	if err != nil {
		log.Fatal("check: failed to USN ID: url parse error", err)
	}
	return strings.Trim(u.Path, "/")
}

func getMarkdown(usnID string) string {
	url := fmt.Sprintf("https://git.launchpad.net/usn.ubuntu.com/plain/content/%s.md", usnID)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal("check: failed to get markdown: http get error", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("check: failed to get markdown: read error", err)
	}

	return string(bodyBytes)
}

func releaseNames(markdown string) []string {
	metadataBytes := []byte(strings.Split(markdown, "---")[1])
	metadata := struct {
		Releases []string `yaml:"releases"`
	}{}
	err := yaml.Unmarshal(metadataBytes, &metadata)
	if err != nil {
		log.Fatal("check: failed to get metadata: parse error", err)
	}
	return metadata.Releases
}

func cveLinks(markdown string) []string {
	re := regexp.MustCompile(`\[CVE-.*\]\((.*)\)`)
	result := []string{}
	for _, match := range re.FindAllStringSubmatch(markdown, -1) {
		if match == nil {
			continue
		}
		if len(match) > 1 && len(match[1]) > 0 {
			result = append(result, match[1])
		}
	}
	return result
}

func cvePriority(url string) string {
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal("check: failed to get cve: http get error", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Fatalf("check: status code error: %d %s", resp.StatusCode, resp.Status)
	}

	// Load the HTML document
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Fatal("check: failed to parse cve html: parse error", err)
	}

	return strings.ToLower(doc.Find(".item:nth-child(2) div:nth-child(2)").Text())
}

func cvePriorities(urls []string) []string {
	priorities := []string{}
	for _, url := range urls {
		priorities = append(priorities, cvePriority(url))
	}
	return priorities
}

func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}

func any(a []string, s []string) bool {
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
