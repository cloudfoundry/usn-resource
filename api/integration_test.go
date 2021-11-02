package api_test

import (
	"fmt"

	"github.com/cloudfoundry/usn-resource/api"
	"github.com/mmcdole/gofeed"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("CVE", func() {
	It("can parse the latest USNs from the website", func() {
		fp := gofeed.NewParser()
		feed, _ := fp.ParseURL("https://usn.ubuntu.com/usn/rss.xml")
		Expect(feed.Items).To(HaveLen(10))

		foundRealPriority := false
		for _, item := range feed.Items {
			usn := api.USNFromFeed(item)
			Expect(len(usn.Releases())).Should(BeNumerically(">", 0), "No releases were found for any usns")

			for _, priority := range usn.CVEs().Priorities() {
				if priority != "unknown" {
					foundRealPriority = true
				}
				Expect(priority).To(MatchRegexp(`^(?i)(critical|high|medium|low|negligible|untriaged|unknown|rejected)$`), fmt.Sprintf("Unknown priority in one of the following CVEs: %v", usn.CVEs()))
			}
		}
		Expect(foundRealPriority).To(BeTrue(), "Priority parsing seems to be broken, expected to find at least one real cve priority in 10 rss feed usns")
	})

	It("returns an unknown priority if CVE cannot be found", func() {
		cve := api.CVE{URL: "http://usn.ubuntu.com/usn/not-found-no-this-really-doenst-exist"}
		Expect(cve.Priority()).To(Equal("unknown"))
	})

	It("parses the priority for a single CVE", func() {
		url := "https://ubuntu.com/security/CVE-2020-15257"
		cve := api.CVE{URL: url}
		Expect(cve.Priority()).To(Equal("medium"))
	})

	It("parses a USN for releases affected", func() {
		usn := api.USN{URL: "https://ubuntu.com/security/notices/USN-4653-1"}
		Expect(usn.IsForRelease("xenial")).To(BeTrue())
	})
})
