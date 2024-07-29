package api_test

import (
	"fmt"

	"github.com/mmcdole/gofeed"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cloudfoundry/usn-resource/api"
)

var _ = Describe("CVE", func() {
	Context("#CVEs", func() {
		It("de-duplicates the list", func() {
			usn := &api.USN{
				URL: "https://ubuntu.com/security/notices/USN-6910-1",
			}
			cves := usn.CVEs()
			expectedCves := api.CVEList{
				api.CVE{URL: "https://ubuntu.com/security/CVE-2015-7559"},
				api.CVE{URL: "https://ubuntu.com/security/CVE-2018-11775"},
				api.CVE{URL: "https://ubuntu.com/security/CVE-2020-13920"},
				api.CVE{URL: "https://ubuntu.com/security/CVE-2021-26117"},
				api.CVE{URL: "https://ubuntu.com/security/CVE-2022-41678"},
				api.CVE{URL: "https://ubuntu.com/security/CVE-2023-46604"},
			}
			Expect(cves).Should(ConsistOf(expectedCves))
		})
	})
	It("can parse the latest USNs from the website", func() {
		By(fmt.Sprintf("parsing the latest USNs from %s", api.FeedURL))
		feed, err := gofeed.NewParser().ParseURL(api.FeedURL)
		Expect(err).NotTo(HaveOccurred())
		Expect(feed.Items).To(HaveLen(10))

		foundRealPriority := false
		for _, item := range feed.Items {
			By(fmt.Sprintf("and checking '%s' at %s", item.Title, item.GUID))
			usn := api.USNFromFeed(item)
			Expect(len(usn.Releases())).Should(
				BeNumerically(">", 0),
				"No releases were found for any usns",
			)

			for _, priority := range usn.CVEs().Priorities() {
				By(fmt.Sprintf("with priority '%s'", priority))
				if priority != "unknown" {
					foundRealPriority = true
				}
				Expect(priority).To(
					MatchRegexp(`^(?i)(critical|high|medium|low|negligible|untriaged|unknown|rejected|not in ubuntu)$`),
					fmt.Sprintf("Unknown priority in one of the following CVEs: %v", usn.CVEs()),
				)
			}
		}

		Expect(foundRealPriority).To(
			BeTrue(),
			"Priority parsing seems to be broken, expected to find at least one real cve priority in 10 rss feed usns",
		)
	})

	It("returns an unknown priority if CVE cannot be found", func() {
		cve := api.CVE{URL: "https://usn.ubuntu.com/usn/not-found-no-this-really-doenst-exist"}
		Expect(cve.Priority()).To(Equal("unknown"))
	})

	It("parses the priority for a single CVE", func() {
		url := "https://ubuntu.com/security/CVE-2020-15257"
		cve := api.CVE{URL: url}
		Expect(cve.Priority()).To(Equal("medium"))
	})

	It("parses a USN for releases affected", func() {
		usn := api.USN{URL: "https://ubuntu.com/security/notices/USN-6912-1"}
		Expect(usn.IsForRelease("noble")).To(BeTrue())
	})
})
