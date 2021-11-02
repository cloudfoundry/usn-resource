package api

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	rss "github.com/mmcdole/gofeed"
)

type USN struct {
	URL string

	markdownCache string
	metadataCache *metadata
	rssMetadata rssMetadata
}
type rssMetadata struct {
	Title       string   `yaml:"title"`
	Description string   `yaml:"description"`
	Date        string   `yaml:"date"`
}

type usnMetadata struct {
	Releases    []string
}

type metadata struct {
	rssMetadata
	usnMetadata
}

var lineToName = map[string]string{
	"ubuntu-14.04-lts": "trusty",
	"ubuntu-16.04-lts": "xenial",
	"ubuntu-18.04-lts": "bionic",
}

func USNFromFeed(item *rss.Item) *USN{
	_, err := url.Parse(item.GUID)
	if err != nil {
		log.Fatal("usn: failed to USN ID: url parse error", err)
	}
	rssMetadata := rssMetadata{
		Title: item.Title,
		Description: item.Description,
	}
	return &USN{URL: item.GUID, rssMetadata: rssMetadata}
}

func (u *USN) USNPage() string {
	if u.markdownCache != "" {
		return u.markdownCache
	}

	resp, err := http.Get(u.URL)
	if err != nil {
		log.Fatal("usn: failed to get markdown: http get error", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("cve: failed to parse html: parse error", err)
	}

	u.markdownCache = string(bodyBytes)
	return u.markdownCache
}

func (u *USN) metadata() metadata {
	if u.metadataCache != nil {
		return *u.metadataCache
	}
	metadataSection := u.USNPage()
	re := regexp.MustCompile(`/security/notices\?release=([^"]*)`)
	releaseMatches := re.FindAllStringSubmatch(metadataSection, -1)

	releases := []string{}
	for _, match := range releaseMatches {
		if match == nil {
			continue
		}
		if len(match) > 1 && len(match[1]) > 0 {
			releases = append(releases, match[1])
		}
	}

	metadata := &metadata{u.rssMetadata,usnMetadata{Releases: releases} }
	u.metadataCache = metadata
	return *metadata
}

func (u *USN) Title() string {
	return u.metadata().Title
}

func (u *USN) Description() string {
	return u.metadata().Description
}

func (u *USN) Date() string {
	return u.metadata().Date
}

func (u *USN) Releases() []string {
	return u.metadata().Releases
}

func (u *USN) CVEs() CVEList {
	parsedUrl, err := url.Parse(u.URL)

	if err != nil {
		return CVEList{}
	}

	re := regexp.MustCompile(`href=\"((/|http).*CVE-.*)\">CVE-`)
	links := []string{}
	for _, match := range re.FindAllStringSubmatch(u.USNPage(), -1) {
		if match == nil {
			continue
		}
		if len(match) > 1 && len(match[1]) > 0 {
			if strings.HasPrefix(match[1], "/") {
				links = append(links, fmt.Sprintf("%v://%v%v", parsedUrl.Scheme, parsedUrl.Hostname(), match[1]))
			} else {
				links = append(links, match[1])
			}
		}
	}
	return cvesFromURLs(links)
}

func (u *USN) IsForRelease(release string) bool {
	if releaseKey, ok := lineToName[release]; ok {
		release = releaseKey
	}

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
