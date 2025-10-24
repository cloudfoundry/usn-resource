package api_test

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"net/http"
	"os"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	. "github.com/cloudfoundry/usn-resource/api"
)

var _ = Describe("Oval USN", func() {
	Context("ParseOvalData", func() {
		var XML = []byte(`<oval_definitions xmlns:oval="http://oval.mitre.org/XMLSchema/oval-common-5">
	<generator>
		<oval:timestamp>SOME TIMESTAMP</oval:timestamp>
	</generator>
	<definitions>
		<definition id="oval:com.ubuntu.noble:def:77861000000" version="1" class="patch">
            <metadata>
                <title>USN-7786-1 -- OpenSSL vulnerabilities</title>
                <affected family="unix">
                    <platform>Ubuntu 24.04 LTS</platform>
                </affected>
                <reference source="USN" ref_id="USN-7786-1" ref_url="https://ubuntu.com/security/notices/USN-7786-1"/>
                <reference source="CVE" ref_id="CVE-2025-9231" ref_url="https://ubuntu.com/security/CVE-2025-9231"/>
                <reference source="CVE" ref_id="CVE-2025-9232" ref_url="https://ubuntu.com/security/CVE-2025-9232"/>
                <reference source="CVE" ref_id="CVE-2025-9230" ref_url="https://ubuntu.com/security/CVE-2025-9230"/>
                <description>Stanislav Fort discovered that OpenSSL incorrectly handled memory when trying to decrypt CMS messages encrypted with password-based encryption. An attacker could possibly use this issue to cause a denial of service or execute arbitrary code. (CVE-2025-9230)  Stanislav Fort discovered that OpenSSL had a timing side-channel in SM2 signature computations on ARM platforms. A remote attacker could possibly use this issue to recover private data. This issue only affected Ubuntu 25.04. (CVE-2025-9231)  Stanislav Fort discovered that OpenSSL incorrectly handled memory during HTTP requests when "no_proxy" environment variable is set. An attacker could possibly use this issue to cause a denial of service. This issue only affected Ubuntu 25.04. (CVE-2025-9232)  Update Instructions:  Run 'sudo pro fix USN-7786-1' to fix the vulnerability. The problem can be corrected by updating your system to the following package versions:  libssl-dev - 3.0.13-0ubuntu3.6 libssl-doc - 3.0.13-0ubuntu3.6 libssl3t64 - 3.0.13-0ubuntu3.6 openssl - 3.0.13-0ubuntu3.6 No subscription required</description>
                <advisory from="security@ubuntu.com">
                    <severity>Medium</severity>
                    <issued date="2025-09-30"/>
                    <cve href="https://ubuntu.com/security/CVE-2025-9231" priority="medium" public="20250930" cvss_score="6.5" cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:L" cvss_severity="medium" usns="7786-1">CVE-2025-9231</cve>
                    <cve href="https://ubuntu.com/security/CVE-2025-9232" priority="low" public="20250930" cvss_score="5.9" cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" cvss_severity="medium" usns="7786-1">CVE-2025-9232</cve>
                    <cve href="https://ubuntu.com/security/CVE-2025-9230" priority="medium" public="20250930" cvss_score="7.5" cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" cvss_severity="high" usns="7786-1">CVE-2025-9230</cve>
                    
                </advisory>
            </metadata>
            <criteria>
                <extend_definition definition_ref="oval:com.ubuntu.noble:def:100" comment="Ubuntu 24.04 LTS (noble) is installed." applicability_check="true" />
                <criteria operator="OR">
                    <criterion test_ref="oval:com.ubuntu.noble:tst:778610000000" comment="Long Term Release" />
                </criteria>
            </criteria>
        </definition>
	</definitions>
</oval_definitions>`)

		It("parses the USNs", func() {
			ovalData, err := ParseOvalData(XML)
			Expect(err).To(BeNil())
			Expect(ovalData.Timestamp).To(Equal("SOME TIMESTAMP"))
			Expect(len(ovalData.Definitions)).To(Equal(1))

			cves := ovalData.Definitions[0].Metadata.Advisory.CVEs
			Expect(len(cves)).To(Equal(3))
			Expect(cves[2].URL).To(Equal("https://ubuntu.com/security/CVE-2025-9230"))
			Expect(cves[2].Priority).To(Equal("medium"))
			Expect(cves[2].CVSSSeverity).To(Equal("high"))

			Expect(ovalData.Definitions[0].Metadata.GetUSNUrl()).To(Equal("https://ubuntu.com/security/notices/USN-7786-1"))
		})
	})

	Context("GetOvalRawData", func() {
		var ignoreCache bool

		BeforeEach(func() {
			os.Remove(ETagPath)          //nolint:errcheck
			os.Remove(CachedOvalXMLPath) //nolint:errcheck
			ignoreCache = false
		})

		Context("valid ubuntu os", func() {
			It("returns raw data", func() {
				data, err := GetOvalRawData("jammy", ignoreCache)
				Expect(err).To(BeNil())
				Expect(len(data) > 0).To(BeTrue())
				decoder := xml.NewDecoder(bytes.NewReader(data))

				// Decode the XML into a dummy struct
				// This will check for well-formedness
				var dummy struct{}
				if err := decoder.Decode(&dummy); err != nil {
					Fail("invalid XML")
				}
			})
		})
		Context("given ubuntu version number", func() {
			It("returns raw data", func() {
				data, err := GetOvalRawData("ubuntu-22.04-lts", ignoreCache)
				Expect(err).To(BeNil())
				Expect(len(data) > 0).To(BeTrue())
				decoder := xml.NewDecoder(bytes.NewReader(data))

				// Decode the XML into a dummy struct
				// This will check for well-formedness
				var dummy struct{}
				if err := decoder.Decode(&dummy); err != nil {
					Fail("invalid XML")
				}
			})
		})
		Context("given neither os name or ubuntu version", func() {
			It("errors", func() {
				_, err := GetOvalRawData("randomOs", ignoreCache)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(Equal("Unknown os: randomOs"))
			})
		})
		Context("when there exists a etag", func() {
			Context("when the existing etag matches the url's etag", func() {
				It("returns the contents of the existing file", func() {
					osStr := "jammy"
					url := fmt.Sprintf("https://security-metadata.canonical.com/oval/com.ubuntu.%s.usn.oval.xml.bz2", osStr)
					resp, err := http.Head(url)
					Expect(err).ToNot(HaveOccurred())
					existingETag := resp.Header.Get("etag")
					err = os.WriteFile(ETagPath, []byte(existingETag), 0644)
					Expect(err).ToNot(HaveOccurred())
					cachedOvalContents := "cached-oval-contents"
					err = os.WriteFile(CachedOvalXMLPath, []byte(cachedOvalContents), 0644)
					Expect(err).ToNot(HaveOccurred())

					contents, err := GetOvalRawData(osStr, ignoreCache)
					Expect(err).ToNot(HaveOccurred())
					Expect(contents).To(Equal([]byte(cachedOvalContents)))
				})
			})

			Context("when the existing etag does not match the url's etag", func() {
				It("returns the xml from the url and caches the etag and xml", func() {
					err := os.WriteFile(ETagPath, []byte("not-an-etag"), 0644)
					Expect(err).ToNot(HaveOccurred())
					cachedOvalContents := "cached-oval-contents"
					os.WriteFile(CachedOvalXMLPath, []byte(cachedOvalContents), 0644) //nolint:errcheck

					contents, err := GetOvalRawData("jammy", ignoreCache)
					Expect(err).ToNot(HaveOccurred())
					Expect(len(contents) > 100).To(BeTrue())

					existingEtag, _ := os.ReadFile(ETagPath) //nolint:errcheck
					Expect(string(existingEtag)).ToNot(Equal("not-an-etag"))
					cachedXML, _ := os.ReadFile(CachedOvalXMLPath) //nolint:errcheck
					Expect(len(cachedXML) > 100).To(BeTrue())
				})
			})

			Context("when the cache file is empty", func() {
				It("returns an error", func() {
					osStr := "jammy"
					url := fmt.Sprintf("https://security-metadata.canonical.com/oval/com.ubuntu.%s.usn.oval.xml.bz2", osStr)
					resp, err := http.Head(url)
					Expect(err).ToNot(HaveOccurred())
					existingETag := resp.Header.Get("etag")
					err = os.WriteFile(ETagPath, []byte(existingETag), 0644)
					Expect(err).ToNot(HaveOccurred())

					cachedOvalContents := ""
					err = os.WriteFile(CachedOvalXMLPath, []byte(cachedOvalContents), 0644)
					Expect(err).ToNot(HaveOccurred())

					_, err = GetOvalRawData(osStr, ignoreCache)
					Expect(err).To(MatchError("cached oval data is blank"))
				})
			})

			Context("when cache is disabled", func() {
				BeforeEach(func() {
					ignoreCache = true
				})

				Context("when the existing etag matches the url's etag", func() {
					It("does not read from the cache", func() {
						osStr := "jammy"
						url := fmt.Sprintf("https://security-metadata.canonical.com/oval/com.ubuntu.%s.usn.oval.xml.bz2", osStr)
						resp, err := http.Head(url)
						Expect(err).ToNot(HaveOccurred())

						existingETag := resp.Header.Get("etag")
						err = os.WriteFile(ETagPath, []byte(existingETag), 0644)
						Expect(err).ToNot(HaveOccurred())

						cachedOvalContents := "cached-oval-contents"
						err = os.WriteFile(CachedOvalXMLPath, []byte(cachedOvalContents), 0644)
						Expect(err).ToNot(HaveOccurred())

						By("reading new data from the url")
						contents, err := GetOvalRawData("jammy", ignoreCache)
						Expect(err).ToNot(HaveOccurred())
						Expect(len(contents) > 100).To(BeTrue())

						By("writing the new data to the cache")
						cachedXML, _ := os.ReadFile(CachedOvalXMLPath) //nolint:errcheck
						Expect(len(cachedXML) > 100).To(BeTrue())
					})
				})
			})

		})
	})
})

var _ = Describe("GetCVEPriorities", func() {
	It("returns a list of deduplicated priorities", func() {
		advisory := Advisory{CVEs: []OvalCVE{
			{Priority: "low"},
			{Priority: "low"},
			{Priority: "high"},
		}}
		Expect(advisory.GetCVEPriorities()).To(ConsistOf([]string{"low", "high"}))
	})
})

var _ = Describe("GetCVESeverities", func() {
	It("returns a list of deduplicated severities", func() {
		advisory := Advisory{CVEs: []OvalCVE{
			{CVSSSeverity: "low"},
			{CVSSSeverity: "medium"},
			{CVSSSeverity: "low"},
			{CVSSSeverity: "high"},
		}}
		Expect(advisory.GetCVESeverities()).To(ConsistOf([]string{"low", "medium", "high"}))
	})
})

var _ = Describe("ToUSNMetadata", func() {
	It("converts to USNMetadata", func() {
		cve := OvalCVE{URL: "some-url", Priority: "low", CVSSSeverity: "medium"}
		definition := Definition{Metadata: Metadata{
			Advisory: Advisory{
				CVEs:   []OvalCVE{cve},
				Issued: Issued{Date: "2024-10-22"},
			},
			Title:       "my-definition",
			Description: "some-description",
			References:  []Reference{{Source: "USN", RefUrl: "some-usn-url"}},
		}}

		usnMetadata := definition.ToUSNMetadata("jammy")
		Expect(usnMetadata.URL).To(Equal("some-usn-url"))
		Expect(usnMetadata.Title).To(Equal("my-definition"))
		Expect(usnMetadata.Description).To(Equal("some-description"))
		Expect(usnMetadata.Date).To(Equal("2024-10-22"))
		Expect(usnMetadata.Releases).To(Equal([]string{"jammy"}))
		Expect(usnMetadata.Priorities).To(Equal([]string{"low"}))
		Expect(usnMetadata.Severities).To(Equal([]string{"medium"}))
		Expect(usnMetadata.CVEs).To(Equal([]string{"some-url"}))
	})

	It("converts ubuntu version to os name in releases", func() {
		cve := OvalCVE{URL: "some-url", Priority: "low", CVSSSeverity: "medium"}
		definition := Definition{Metadata: Metadata{
			Advisory: Advisory{
				CVEs:   []OvalCVE{cve},
				Issued: Issued{Date: "2024-10-22"},
			},
			Title:       "my-definition",
			Description: "some-description",
			References:  []Reference{{Source: "USN", RefUrl: "some-usn-url"}},
		}}

		usnMetadata := definition.ToUSNMetadata("ubuntu-22.04-lts")
		Expect(usnMetadata.Releases).To(Equal([]string{"jammy"}))
	})
})
