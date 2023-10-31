package api

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

const unknownPriority = "unknown"

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
	resp, err := getNonBrotliResponse(c.URL)
	if err != nil {
		log.Fatalf("cve: http.Get failed: %v", err)
	}
	defer func(resp *http.Response) {
		err := resp.Body.Close()
		if err != nil {
			log.Printf("cve: error closing resp.Body: %v", err)
		}
	}(resp)

	if resp.StatusCode != 200 {
		log.Printf("cve: non-success HTTP Status: '%+v' -- defaulting priority to '%s'", resp.Status, unknownPriority)
		return unknownPriority
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
		log.Printf("cve: unable to find a priority for CVE at '%s'. It matches known page structure, so parsing may still be valid. Returning a status of '%s'", c.URL, unknownPriority)
		return unknownPriority
	}

	log.Printf("cve: unable to find a priority for CVE at '%s' - it is likely that the structure of the CVE page has changed and the parsing is no longer valid", c.URL)
	log.Printf("cve: response.Header 'Content-Encoding': '%s'", resp.Header.Get("Content-Encoding"))
	panic(fmt.Sprintf("Unable to parse priority for CVE: '%s'", c.URL))
}

func (l CVEList) Priorities() []string {
	priorities := make([]string, 0, len(l))
	for _, c := range l {
		priorities = append(priorities, c.Priority())
	}
	return priorities
}
