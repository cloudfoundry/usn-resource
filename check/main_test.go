package main_test

import (
	"path/filepath"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/cloudfoundry/usn-resource/api"
	. "github.com/cloudfoundry/usn-resource/check"
)

var _ = Describe("GetLatestVersion", func() {
	var (
		priorities []string
		severities []string
	)

	Context("when there is no version from request", func() {
		Context("when there are priorities that match", func() {
			BeforeEach(func() {
				priorities = []string{"high"}
			})

			It("returns the correct list of versions", func() {
				cve := api.OvalCVE{URL: "some-url", Priority: "low", CVSSSeverity: "medium"}
				definition := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve}}, References: []api.Reference{{Source: "USN", RefUrl: "usn1-url"}}}}

				cve2 := api.OvalCVE{URL: "some-url2", Priority: "low", CVSSSeverity: "medium"}
				cve3 := api.OvalCVE{URL: "some-url3", Priority: "high", CVSSSeverity: "medium"}
				definition2 := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve2, cve3}}, References: []api.Reference{{Source: "USN", RefUrl: "usn2-url"}}}}

				cve4 := api.OvalCVE{URL: "some-url4", Priority: "high", CVSSSeverity: "medium"}
				definition3 := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve4}}, References: []api.Reference{{Source: "USN", RefUrl: "usn3-url"}}}}

				definitions := api.OvalDefinitions{Definitions: []api.Definition{definition, definition2, definition3}}
				versions := GetLatestVersions(definitions, api.Version{GUID: ""}, priorities, severities)

				Expect(versions).To(Equal([]api.Version{{GUID: "usn2-url"}, {GUID: "usn3-url"}}))
			})
		})

		Context("when there are severities that match", func() {
			BeforeEach(func() {
				severities = []string{"high"}
			})

			It("returns the correct list of versions", func() {
				cve := api.OvalCVE{URL: "some-url", Priority: "medium", CVSSSeverity: "low"}
				definition := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve}}, References: []api.Reference{{Source: "USN", RefUrl: "usn1-url"}}}}

				cve2 := api.OvalCVE{URL: "some-url2", Priority: "medium", CVSSSeverity: "medium"}
				cve3 := api.OvalCVE{URL: "some-url3", Priority: "medium", CVSSSeverity: "high"}
				definition2 := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve2, cve3}}, References: []api.Reference{{Source: "USN", RefUrl: "usn2-url"}}}}

				cve4 := api.OvalCVE{URL: "some-url4", Priority: "medium", CVSSSeverity: "high"}
				definition3 := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve4}}, References: []api.Reference{{Source: "USN", RefUrl: "usn3-url"}}}}

				definitions := api.OvalDefinitions{Definitions: []api.Definition{definition, definition2, definition3}}
				versions := GetLatestVersions(definitions, api.Version{GUID: ""}, priorities, severities)

				Expect(versions).To(Equal([]api.Version{{GUID: "usn2-url"}, {GUID: "usn3-url"}}))
			})
		})

		Context("when there are no priorities or severities that match", func() {
			BeforeEach(func() {
				priorities = []string{"high"}
				severities = []string{"high"}
			})

			It("returns empty versions", func() {
				cve := api.OvalCVE{URL: "some-url", Priority: "low", CVSSSeverity: "low"}
				definition := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve}}, References: []api.Reference{{Source: "USN", RefUrl: "usn1-url"}}}}
				definitions := api.OvalDefinitions{Definitions: []api.Definition{definition}}
				versions := GetLatestVersions(definitions, api.Version{}, priorities, severities)
				Expect(len(versions)).To(Equal(0))
			})
		})

		Context("when the definition is for a Livepatch Security Notice (LSN)", func() {
			It("does not include the version", func() {
				cve := api.OvalCVE{URL: "some-url", Priority: "high"}
				definition := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve}}, References: []api.Reference{{Source: "USN", RefUrl: "https://ubuntu.com/security/notices/USN-123"}}}}

				cve2 := api.OvalCVE{URL: "some-url2", Priority: "low"}
				cve3 := api.OvalCVE{URL: "some-url3", Priority: "high"}
				definition2 := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve2, cve3}}, References: []api.Reference{{Source: "USN", RefUrl: "https://ubuntu.com/security/notices/LSN-456"}}}}

				cve4 := api.OvalCVE{URL: "some-url4", Priority: "high"}
				definition3 := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve4}}, References: []api.Reference{{Source: "USN", RefUrl: "https://ubuntu.com/security/notices/USN-789"}}}}

				definitions := api.OvalDefinitions{Definitions: []api.Definition{definition, definition2, definition3}}
				versions := GetLatestVersions(definitions, api.Version{GUID: ""}, priorities, severities)

				Expect(versions).To(Equal([]api.Version{{GUID: "https://ubuntu.com/security/notices/USN-123"}, {GUID: "https://ubuntu.com/security/notices/USN-789"}}))
			})
		})
	})

	Context("when there is a version from request", func() {
		Context("when there are new versions that match", func() {
			It("returns new versions and the previous version", func() {
				cve := api.OvalCVE{URL: "some-url", Priority: "high"}
				definition := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve}}, References: []api.Reference{{Source: "USN", RefUrl: "usn1-url"}}}}

				cve2 := api.OvalCVE{URL: "some-url2", Priority: "low"}
				cve3 := api.OvalCVE{URL: "some-url3", Priority: "high"}
				definition2 := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve2, cve3}}, References: []api.Reference{{Source: "USN", RefUrl: "usn2-url"}}}}

				cve4 := api.OvalCVE{URL: "some-url4", Priority: "high"}
				definition3 := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve4}}, References: []api.Reference{{Source: "USN", RefUrl: "usn3-url"}}}}

				cve5 := api.OvalCVE{URL: "some-url5", Priority: "high"}
				definition4 := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve5}}, References: []api.Reference{{Source: "USN", RefUrl: "usn4-url"}}}}

				cve6 := api.OvalCVE{URL: "some-url6", Priority: "medium"}
				definition5 := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve6}}, References: []api.Reference{{Source: "USN", RefUrl: "usn5-url"}}}}

				definitions := api.OvalDefinitions{Definitions: []api.Definition{definition, definition2, definition3, definition4, definition5}}
				versions := GetLatestVersions(definitions, api.Version{GUID: "usn3-url"}, priorities, severities)
				Expect(versions).To(Equal([]api.Version{{GUID: "usn3-url"}, {GUID: "usn4-url"}}))
			})
		})
	})
})

var _ = Describe("GetLatestVersions with current-format OVAL data", func() {
	var (
		priorities = []string{"high", "critical"}
		severities = []string{"high", "critical"}
	)

	usnDefinition := func(refURL string, priority string) api.Definition {
		return api.Definition{Metadata: api.Metadata{
			Advisory:   api.Advisory{CVEs: []api.OvalCVE{{URL: "cve-url", Priority: priority}}},
			References: []api.Reference{{Source: "USN", RefUrl: refURL}},
		}}
	}

	// Canonical's OVAL generator v2 emits Livepatch notices with source="LSN"
	// rather than source="USN", and places them after every USN definition.
	lsnDefinition := func(refURL string, priority string) api.Definition {
		return api.Definition{Metadata: api.Metadata{
			Advisory:   api.Advisory{CVEs: []api.OvalCVE{{URL: "cve-url", Priority: priority}}},
			References: []api.Reference{{Source: "LSN", RefUrl: refURL}},
		}}
	}

	// The class="inventory" definition carries no references at all.
	inventoryDefinition := func() api.Definition {
		return api.Definition{Metadata: api.Metadata{Title: "Check that Ubuntu 22.04 LTS (jammy) is installed."}}
	}

	Context("when a Livepatch notice uses source=\"LSN\"", func() {
		It("does not include the Livepatch notice as a version", func() {
			definitions := api.OvalDefinitions{Definitions: []api.Definition{
				inventoryDefinition(),
				usnDefinition("https://ubuntu.com/security/notices/USN-8528-1", "high"),
				usnDefinition("https://ubuntu.com/security/notices/USN-8536-1", "high"),
				lsnDefinition("https://ubuntu.com/security/notices/LSN-120-1", "high"),
			}}

			versions := GetLatestVersions(definitions, api.Version{GUID: "https://ubuntu.com/security/notices/USN-8528-1"}, priorities, severities)

			Expect(versions).To(Equal([]api.Version{
				{GUID: "https://ubuntu.com/security/notices/USN-8528-1"},
				{GUID: "https://ubuntu.com/security/notices/USN-8536-1"},
			}))
		})
	})

	Context("when a definition has no USN reference", func() {
		It("never emits a version with an empty GUID", func() {
			definitions := api.OvalDefinitions{Definitions: []api.Definition{
				inventoryDefinition(),
				usnDefinition("https://ubuntu.com/security/notices/USN-8536-1", "high"),
				lsnDefinition("https://ubuntu.com/security/notices/LSN-120-1", "high"),
			}}

			versions := GetLatestVersions(definitions, api.Version{GUID: ""}, priorities, severities)

			for _, version := range versions {
				Expect(version.GUID).ToNot(BeEmpty())
			}
		})
	})

	Context("when the previous version is an empty GUID", func() {
		It("does not stop at a definition without a USN reference", func() {
			definitions := api.OvalDefinitions{Definitions: []api.Definition{
				inventoryDefinition(),
				usnDefinition("https://ubuntu.com/security/notices/USN-8528-1", "high"),
				usnDefinition("https://ubuntu.com/security/notices/USN-8536-1", "high"),
				lsnDefinition("https://ubuntu.com/security/notices/LSN-120-1", "high"),
			}}

			versions := GetLatestVersions(definitions, api.Version{GUID: ""}, priorities, severities)

			Expect(versions).To(Equal([]api.Version{
				{GUID: "https://ubuntu.com/security/notices/USN-8528-1"},
				{GUID: "https://ubuntu.com/security/notices/USN-8536-1"},
			}))
		})
	})
})

var _ = Describe("GetLatestVersions against the live Canonical OVAL feed", Ordered, func() {
	var (
		definitions api.OvalDefinitions
		versions    []api.Version
	)

	BeforeAll(func() {
		// GetOvalRawData caches through package-level paths, so point them at a
		// temp dir Ginkgo removes for us rather than sharing /tmp with the api suite.
		cacheDir := GinkgoT().TempDir()
		originalETagPath, originalCachedOvalXMLPath := api.ETagPath, api.CachedOvalXMLPath
		api.ETagPath = filepath.Join(cacheDir, "etag")
		api.CachedOvalXMLPath = filepath.Join(cacheDir, "oval.xml")
		DeferCleanup(func() {
			api.ETagPath, api.CachedOvalXMLPath = originalETagPath, originalCachedOvalXMLPath
		})

		rawData, err := api.GetOvalRawData("jammy")
		Expect(err).ToNot(HaveOccurred())

		definitions, err = api.ParseOvalData(rawData)
		Expect(err).ToNot(HaveOccurred())
		Expect(len(definitions.Definitions)).To(BeNumerically(">", 100))

		versions = GetLatestVersions(definitions, api.Version{}, []string{"high", "critical"}, []string{"high", "critical"})
		Expect(versions).ToNot(BeEmpty())
	})

	It("emits only Ubuntu Security Notice urls", func() {
		for _, version := range versions {
			Expect(version.GUID).To(HavePrefix("https://ubuntu.com/security/notices/USN-"))
		}
	})

	It("emits a USN issued within the last 30 days", func() {
		issuedDates := map[string]string{}
		for _, definition := range definitions.Definitions {
			issuedDates[definition.Metadata.GetUSNUrl()] = definition.Metadata.Advisory.Issued.Date
		}

		newest := ""
		for _, version := range versions {
			// Trim any time component; the feed has used both "2006-01-02"
			// and RFC 3339 for this attribute.
			issued := issuedDates[version.GUID]
			if len(issued) >= 10 && issued[:10] > newest {
				newest = issued[:10]
			}
		}

		newestIssued, err := time.Parse("2006-01-02", newest)
		Expect(err).ToNot(HaveOccurred())
		Expect(newestIssued).To(BeTemporally(">", time.Now().AddDate(0, 0, -30)))
	})
})
