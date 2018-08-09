package api

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	yaml "gopkg.in/yaml.v2"
)

type USN struct {
	ID string

	markdownCache string
}

func USNFromURL(address string) *USN {
	u, err := url.Parse(address)
	if err != nil {
		log.Fatal("usn: failed to USN ID: url parse error", err)
	}
	return &USN{ID: strings.Trim(u.Path, "/")}
}

func (u *USN) markdown() string {
	if u.markdownCache != "" {
		return u.markdownCache
	}

	url := fmt.Sprintf("https://git.launchpad.net/usn.ubuntu.com/plain/content/%s.md", u.ID)
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal("usn: failed to get markdown: http get error", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("usn: failed to get markdown: read error", err)
	}

	u.markdownCache = string(bodyBytes)
	return u.markdownCache
}

func (u *USN) Releases() []string {
	metadataBytes := []byte(strings.Split(u.markdown(), "---")[1])
	metadata := struct {
		Releases []string `yaml:"releases"`
	}{}
	err := yaml.Unmarshal(metadataBytes, &metadata)
	if err != nil {
		log.Fatal("check: failed to get metadata: parse error", err)
	}
	return metadata.Releases
}

func (u *USN) CVEs() CVEList {
	re := regexp.MustCompile(`\[CVE-.*\]\((.*)\)`)
	links := []string{}
	for _, match := range re.FindAllStringSubmatch(u.markdown(), -1) {
		if match == nil {
			continue
		}
		if len(match) > 1 && len(match[1]) > 0 {
			links = append(links, match[1])
		}
	}
	return cvesFromURLs(links)
}

func (u *USN) IsForRelease(release string) bool {
	if contains(u.Releases(), release) {
		return true
	}
	return false
}

func contains(a []string, s string) bool {
	for _, v := range a {
		if v == s {
			return true
		}
	}
	return false
}
