package api

import (
	"log"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

type CVE struct {
	URL string
}

type CVEList []CVE

func cvesFromURLs(urls []string) CVEList {
	cves := make(CVEList, 0, len(urls))
	for _, url := range urls {
		cves = append(cves, CVE{URL: url})
	}
	return cves
}

func (c CVE) Priority() string {
	resp, err := http.Get(c.URL)
	if err != nil {
		log.Fatal("cve: failed to get: http get error", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		log.Printf("cve: status code error: %d %s from %s -- defaulting to high\n", resp.StatusCode, resp.Status, c.URL)
		return "high"
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Fatal("cve: failed to parse html: parse error", err)
	}

	return strings.ToLower(doc.Find(".item:nth-child(2) div:nth-child(2)").Text())
}

func (l CVEList) Priorities() []string {
	priorities := make([]string, 0, len(l))
	for _, c := range l {
		priorities = append(priorities, c.Priority())
	}
	return priorities
}
