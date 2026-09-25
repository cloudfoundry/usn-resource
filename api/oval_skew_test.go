package api_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/cloudfoundry/usn-resource/api"
)

// Canonical serves the OVAL feed from several cache nodes that can be a feed
// generation apart, so consecutive requests may see different content.
var _ = Describe("OVAL feed served by out-of-sync cache nodes", func() {
	var (
		staleFeed, freshFeed []byte
		gets                 atomic.Int32
		headETag             string
		getResponses         []string // feed served by each successive GET; last one repeats
		server               *httptest.Server
	)

	BeforeEach(func() {
		var err error
		staleFeed, err = os.ReadFile(filepath.Join("testdata", "oval-stale.xml.bz2"))
		Expect(err).ToNot(HaveOccurred())
		freshFeed, err = os.ReadFile(filepath.Join("testdata", "oval-fresh.xml.bz2"))
		Expect(err).ToNot(HaveOccurred())
		gets.Store(0)

		server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodHead {
				w.Header().Set("etag", headETag)
				return
			}
			n := int(gets.Add(1)) - 1
			which := getResponses[min(n, len(getResponses)-1)]
			w.Header().Set("etag", which)
			if which == "stale" {
				w.Write(staleFeed) //nolint:errcheck
			} else {
				w.Write(freshFeed) //nolint:errcheck
			}
		}))

		cacheDir := GinkgoT().TempDir()
		origBase, origETag, origXML, origDelay := OvalFeedBaseURL, ETagPath, CachedOvalXMLPath, DefinitionFetchRetryDelay
		OvalFeedBaseURL = server.URL + "/"
		ETagPath = filepath.Join(cacheDir, "etag")
		CachedOvalXMLPath = filepath.Join(cacheDir, "oval.xml")
		DefinitionFetchRetryDelay = 0
		DeferCleanup(func() {
			server.Close()
			OvalFeedBaseURL, ETagPath, CachedOvalXMLPath, DefinitionFetchRetryDelay = origBase, origETag, origXML, origDelay
		})
	})

	Context("GetOvalRawData", func() {
		It("caches the etag of the content it downloaded, not the etag the HEAD request saw", func() {
			headETag = "fresh"
			getResponses = []string{"stale"}

			_, err := GetOvalRawData("jammy")
			Expect(err).ToNot(HaveOccurred())

			cachedETag, err := os.ReadFile(ETagPath)
			Expect(err).ToNot(HaveOccurred())
			Expect(string(cachedETag)).To(Equal("stale"))
		})
	})

	Context("GetDefinitionWithRetry", func() {
		It("refetches past a stale cached copy until the definition appears", func() {
			headETag = "stale"
			getResponses = []string{"stale", "fresh"}

			def, err := GetDefinitionWithRetry("jammy", "https://ubuntu.com/security/notices/USN-2-1")
			Expect(err).ToNot(HaveOccurred())
			Expect(def.Metadata.Title).To(Equal("USN-2-1"))
			Expect(gets.Load()).To(BeEquivalentTo(2))
		})

		It("does not refetch when the first copy has the definition", func() {
			headETag = "stale"
			getResponses = []string{"stale"}

			def, err := GetDefinitionWithRetry("jammy", "https://ubuntu.com/security/notices/USN-1-1")
			Expect(err).ToNot(HaveOccurred())
			Expect(def.Metadata.Title).To(Equal("USN-1-1"))
			Expect(gets.Load()).To(BeEquivalentTo(1))
		})

		It("gives up after DefinitionFetchAttempts downloads", func() {
			headETag = "stale"
			getResponses = []string{"stale"}

			_, err := GetDefinitionWithRetry("jammy", "https://ubuntu.com/security/notices/USN-2-1")
			Expect(err).To(MatchError(ContainSubstring("Unknown definition with id https://ubuntu.com/security/notices/USN-2-1")))
			Expect(err).To(MatchError(ContainSubstring("attempts")))
			Expect(gets.Load()).To(BeEquivalentTo(DefinitionFetchAttempts))
		})
	})
})
