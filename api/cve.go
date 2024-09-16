package api

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/PuerkitoBio/goquery"
)

const (
	unknownPriority  = "unknown"
	rejectedPriority = "rejected"
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
	bodyReader, httpStatusCode, err := responseReaderAndStatus(c.URL)
	if err != nil {
		log.Fatalf("cve: failed to get '%s': %s", c.URL, err)
	}

	if httpStatusCode != http.StatusOK {
		log.Printf("cve: non-success HTTP Status: '%+v' -- defaulting priority to '%s'", httpStatusCode, unknownPriority)
		return unknownPriority
	}

	doc, err := goquery.NewDocumentFromReader(bodyReader)
	if err != nil {
		log.Fatal("cve: failed to parse html: parse error", err)
	}

	// The jquery path is to get the priority box on the html page
	// if its not on the page, could mean the cve is rejected or unknown
	priorityNode := doc.Find("#main-content > section.p-strip.is-shallow.u-no-padding--bottom > div > div > div > div:nth-child(2) > div > div > p > strong")

	// A CVE page can be missing a priority box. See: https://ubuntu.com/security/CVE-2021-25219
	if priorityNode.Length() == 0 {
		descriptionNode := doc.Find("#description > p")
		// If a CVE has been marked as "Rejected" on the CVE page, the element where priority is displayed
		// is not shown on the page, for example: https://ubuntu.com/security/CVE-2024-27423
		if strings.Contains(descriptionNode.Text(), "** REJECT **") {
			return rejectedPriority
		}

		// To ensure our parsing is not broken while allowing this case, if we don't find a priority or
		// the word rejected, we return unknown
		log.Printf("cve: unable to find a priority for CVE at '%s'. It matches known page structure, so parsing may still be valid. Returning a status of '%s'", c.URL, unknownPriority)
		return unknownPriority
	}

	priorityParts := strings.Split(priorityNode.Text(), " ")
	result := strings.ToLower(priorityParts[len(priorityParts)-1])

	if result != "" {
		return result
	}

	log.Printf("cve: unable to find a priority for CVE at '%s' - it is likely that the structure of the CVE page has changed and the parsing is no longer valid", c.URL)
	panic(fmt.Sprintf("Unable to parse priority for CVE: '%s'", c.URL))
}

func (l CVEList) Priorities() []string {
	priorities := make([]string, 0, len(l))
	for _, c := range l {
		priorities = append(priorities, c.Priority())
	}
	return priorities
}
