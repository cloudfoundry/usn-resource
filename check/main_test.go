package main_test

import (
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

			Context("when there is no definition for the version in the request", func() {
				It("doesn't return new versions", func() {
					cve := api.OvalCVE{URL: "some-url", Priority: "high"}
					definition := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve}}, References: []api.Reference{{Source: "USN", RefUrl: "usn1-url"}}}}

					cve2 := api.OvalCVE{URL: "some-url2", Priority: "low"}
					cve3 := api.OvalCVE{URL: "some-url3", Priority: "high"}
					definition2 := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve2, cve3}}, References: []api.Reference{{Source: "USN", RefUrl: "usn2-url"}}}}

					cve4 := api.OvalCVE{URL: "some-url4", Priority: "high"}
					definition3 := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve4}}, References: []api.Reference{{Source: "USN", RefUrl: "usn3-url"}}}}

					definitions := api.OvalDefinitions{Definitions: []api.Definition{definition, definition2, definition3}}
					versions := GetLatestVersions(definitions, api.Version{GUID: "usn4-url"}, priorities, severities)
					Expect(versions).To(Equal([]api.Version{}))
				})
			})
		})
	})
})
