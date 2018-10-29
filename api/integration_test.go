package api_test

import (
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
		for _, item := range feed.Items {
			usn := api.USNFromURL(item.GUID)
			for _, release := range usn.Releases() {
				Expect(release).To(MatchRegexp(`ubuntu-.*`))
			}
			for _, priority := range usn.CVEs().Priorities() {
				Expect(priority).To(MatchRegexp(`^(?i)(critical|high|medium|low|negligible|untriaged|unknown)$`))
			}
		}
	})

	It("returns an unknown priority if CVE cannot be found", func() {
		cve := api.CVE{URL: "http://usn.ubuntu.com/usn/not-found-no-this-really-doenst-exist"}
		Expect(cve.Priority()).To(Equal("unknown"))
	})
})
