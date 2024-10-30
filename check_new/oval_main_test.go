package check_new_test

import (
	"github.com/cloudfoundry/usn-resource/api"
	. "github.com/cloudfoundry/usn-resource/check_new"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("GetLatestVersion", func() {
	Context("when there is no version from request", func() {
		Context("when there are priorities that match", func() {
			It("returns the correct list of versions", func() {
				cve := api.OvalCVE{URL: "some-url", Priority: "low"}
				definition := api.Definition{Id: "usn1", Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve}}}}

				cve2 := api.OvalCVE{URL: "some-url2", Priority: "low"}
				cve3 := api.OvalCVE{URL: "some-url3", Priority: "high"}
				definition2 := api.Definition{Id: "usn2", Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve2, cve3}}}}

				cve4 := api.OvalCVE{URL: "some-url4", Priority: "high"}
				definition3 := api.Definition{Id: "usn3", Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve4}}}}

				definitions := api.OvalDefinitions{Definitions: []api.Definition{definition, definition2, definition3}}
				versions, err := GetLatestVersions(definitions, Version{GUID: ""}, []string{"high"})

				Expect(err).To(BeNil())
				Expect(versions).To(Equal([]Version{{GUID: "usn2"}, {GUID: "usn3"}}))
			})
		})

		Context("when there are no priorities that match", func() {
			It("returns empty versions", func() {
				cve := api.OvalCVE{URL: "some-url", Priority: "low"}
				definition := api.Definition{Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve}}}}
				definitions := api.OvalDefinitions{Definitions: []api.Definition{definition}}
				versions, err := GetLatestVersions(definitions, Version{}, []string{"high"})
				Expect(err).To(BeNil())
				Expect(len(versions)).To(Equal(0))
			})
		})
	})

	Context("when there is a version from request", func() {
		Context("when there are new versions that match", func() {
			It("returns new versions", func() {
				cve := api.OvalCVE{URL: "some-url", Priority: "high"}
				definition := api.Definition{Id: "usn1", Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve}}}}

				cve2 := api.OvalCVE{URL: "some-url2", Priority: "low"}
				cve3 := api.OvalCVE{URL: "some-url3", Priority: "high"}
				definition2 := api.Definition{Id: "usn2", Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve2, cve3}}}}

				cve4 := api.OvalCVE{URL: "some-url4", Priority: "high"}
				definition3 := api.Definition{Id: "usn3", Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve4}}}}

				cve5 := api.OvalCVE{URL: "some-url5", Priority: "high"}
				definition4 := api.Definition{Id: "usn4", Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve5}}}}

				cve6 := api.OvalCVE{URL: "some-url6", Priority: "medium"}
				definition5 := api.Definition{Id: "usn5", Metadata: api.Metadata{Advisory: api.Advisory{CVEs: []api.OvalCVE{cve6}}}}

				definitions := api.OvalDefinitions{Definitions: []api.Definition{definition, definition2, definition3, definition4, definition5}}
				versions, err := GetLatestVersions(definitions, Version{GUID: "usn3"}, []string{"high"})
				Expect(err).To(BeNil())
				Expect(versions).To(Equal([]Version{{GUID: "usn4"}}))
			})
		})
	})
})
