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
		log.Fatalf("cve: failed to get %s http get error - %s", c.URL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		priority := "unknown"
		log.Printf("cve: status code error: %d %s from %s -- defaulting to %s\n", resp.StatusCode, resp.Status, c.URL, priority)
		return priority
	}

	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		log.Fatal("cve: failed to parse html: parse error", err)
	}

	priority := strings.ToLower(doc.Find(".cve-status-box:first-of-type .p-heading--4").Text())
	result := strings.TrimSpace(priority)

	if result != "" {
		return result
	}

	// If a CVE has been marked as "Rejected" on the CVE page, the element where priority is displayed
	// comes under a different CSS path.
	priority = strings.ToLower(doc.Find(".cve-status-box--highlight > .p-heading--four").Text())
	result = strings.TrimSpace(priority)

	if result != "" {
		return result
	}

	// A CVE page can be missing a priority box. See: https://ubuntu.com/security/CVE-2021-25219
	// To ensure our parsing is not broken while allowing this case, look for a very specific
	// column entry where the priority would normally go, ensure it exists, and is blank
	priorityNode := doc.Find("#main-content > .p-strip > .row:first-child > .col-3")
	result = strings.TrimSpace(priorityNode.Text())
	if priorityNode.Length() != 0 && result == "" {
		log.Printf("cve: unable to find a priority for CVE at '%s'. It matches known page structure, so parsing may still be valid. Returning a status of 'unknown'", c.URL)
		return "unknown"
	}

	log.Fatalf("cve: unable to find a priority for CVE at '%s'. it is likely that the structure of the CVE page has changed and the parsing is no longer valid", c.URL)
	panic("Unable to parse priority for CVE")
}

func (l CVEList) Priorities() []string {
	priorities := make([]string, 0, len(l))
	for _, c := range l {
		priorities = append(priorities, c.Priority())
	}
	return priorities
}
