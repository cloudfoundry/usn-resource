package api_test

import (
	"bytes"
	"encoding/xml"
	. "github.com/cloudfoundry/usn-resource/api"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("Oval USN", func() {
	Context("ParseOvalData", func() {
		var XML = []byte(`<oval_definitions>
	<definitions>
		<definition id="oval:com.ubuntu.jammy:def:1061000000" version="1" class="patch">
            <metadata>
                <title>LSN-0106-1 -- Kernel Live Patch Security Notice</title>
                <affected family="unix">
                    <platform>Ubuntu 22.04 LTS</platform>
                </affected>
                <reference source="USN" ref_id="LSN-0106-1" ref_url="https://ubuntu.com/security/notices/LSN-0106-1"/>
                <reference source="CVE" ref_id="CVE-2024-36016" ref_url="https://ubuntu.com/security/CVE-2024-36016"/>
                <reference source="CVE" ref_id="CVE-2024-26585" ref_url="https://ubuntu.com/security/CVE-2024-26585"/>
                <reference source="CVE" ref_id="CVE-2023-52620" ref_url="https://ubuntu.com/security/CVE-2023-52620"/>
                <description>In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: disallow timeout for anonymous sets Never used from userspace, disallow these parameters.(CVE-2023-52620)  In the Linux kernel, the following vulnerability has been resolved: tls: fix race between tx work scheduling and socket close Similarly to previous commit, the submitting thread (recvmsg/sendmsg) may exit as soon as the async crypto handler calls complete(). Reorder scheduling the work before calling complete(). This seems more logical in the first place, as it's the inverse order of what the submitting thread will do.(CVE-2024-26585)  In the Linux kernel, the following vulnerability has been resolved: tty: n_gsm: fix possible out-of-bounds in gsm0_receive() Assuming the following: - side A configures the n_gsm in basic option mode - side B sends the header of a basic option mode frame with data length 1 - side A switches to advanced option mode - side B sends 2 data bytes which exceeds gsm-&gt;len Reason: gsm-&gt;len is not used in advanced option mode. - side A switches to basic option mode - side B keeps sending until gsm0_receive() writes past gsm-&gt;buf Reason: Neither gsm-&gt;state nor gsm-&gt;len have been reset after reconfiguration. Fix this by changing gsm-&gt;count to gsm-&gt;len comparison from equal to less than. Also add upper limit checks against the constant MAX_MRU in gsm0_receive() and gsm1_receive() to harden against memory corruption of gsm-&gt;len and gsm-&gt;mru. All other checks remain as we still need to limit the data according to the user configuration and actual payload size.(CVE-2024-36016)  To check your kernel type and Livepatch version, enter this command:  canonical-livepatch status  lkp_Ubuntu_5_15_0[_|\d]+_aws_(\d+) - 106 lkp_Ubuntu_5_15_0[_|\d]+_azure_(\d+) - 106 lkp_Ubuntu_5_15_0[_|\d]+_gcp_(\d+) - 106 lkp_Ubuntu_5_15_0[_|\d]+_linux_(\d+) - 106 lkp_Ubuntu_5_15_0[_|\d]+_gke_(\d+) - 106 lkp_Ubuntu_5_15_0[_|\d]+_ibm_(\d+) - 106 lkp_Ubuntu_5_15_0[_|\d]+_oracle_(\d+) - 106 Livepatch subscription required</description>
                <advisory from="security@ubuntu.com">
                    <severity>High</severity>
                    <issued date="2024-08-20"/>
                    <cve href="https://ubuntu.com/security/CVE-2024-36016" priority="high" public="20240529" usns="6923-1,6921-1,6924-1,6926-1,6921-2,6923-2,6927-1,6924-2,6938-1,6926-2,6952-1,6953-1,6926-3,6956-1,6957-1,6952-2,6979-1,7019-1">CVE-2024-36016</cve>
                    <cve href="https://ubuntu.com/security/CVE-2024-26585" priority="high" public="20240221" cvss_score="4.7" cvss_vector="CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:N/I:N/A:H" cvss_severity="medium" usns="6818-1,6819-1,6820-1,6821-1,6818-2,6821-2,6828-1,6820-2,6821-3,6819-2,6819-3,6818-3,6821-4,6818-4,6819-4,6871-1,6892-1,6919-1,6924-1,6924-2,6953-1,6979-1">CVE-2024-26585</cve>
                    <cve href="https://ubuntu.com/security/CVE-2023-52620" priority="high" public="20240321" usns="6820-1,6821-1,6821-2,6828-1,6820-2,6821-3,6821-4,6871-1,6892-1,6896-1,6896-2,6896-3,6896-4,6896-5,6919-1,6926-1,6938-1,6926-2,6926-3">CVE-2023-52620</cve>
                    
                </advisory>
            </metadata>
            <criteria>
                <extend_definition definition_ref="oval:com.ubuntu.jammy:def:100" comment="Ubuntu 22.04 LTS (jammy) is installed." applicability_check="true" />
                <criteria operator="OR">
                    <criteria operator="AND">
                        <criterion test_ref="oval:com.ubuntu.jammy:tst:10610000001" comment="Long Term Support" />
                        <criterion test_ref="oval:com.ubuntu.jammy:tst:10610000000" comment="Long Term Support" />
                    </criteria>
                </criteria>
            </criteria>
        </definition>
	</definitions>
</oval_definitions>`)

		It("parses the USNs", func() {
			ovalData, err := ParseOvalData(XML)
			Expect(err).To(BeNil())
			Expect(len(ovalData.Definitions)).To(Equal(1))
			cves := ovalData.Definitions[0].Metadata.Advisory.CVEs
			Expect(len(cves)).To(Equal(3))
			Expect(cves[0].URL).To(Equal("https://ubuntu.com/security/CVE-2024-36016"))
			Expect(cves[0].Priority).To(Equal("high"))

			Expect(ovalData.Definitions[0].Metadata.GetUSNUrl()).To(Equal("https://ubuntu.com/security/notices/LSN-0106-1"))
		})
	})

	Context("GetOvalRawData", func() {
		Context("valid ubuntu os", func() {
			It("returns raw data", func() {
				data, err := GetOvalRawData("jammy")
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
				data, err := GetOvalRawData("ubuntu-22.04-lts")
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
				_, err := GetOvalRawData("randomOs")
				Expect(err).ToNot(BeNil())
				Expect(err.Error()).To(Equal("Unknown os: randomOs"))
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
		Expect(advisory.GetCVEPriorities()).To(Equal([]string{"low", "high"}))
	})
})

var _ = Describe("ToUSNMetadata", func() {
	It("converts to USNMetadata", func() {
		cve := OvalCVE{URL: "some-url", Priority: "low"}
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
		Expect(usnMetadata.CVEs).To(Equal([]string{"some-url"}))
	})

	It("converts ubuntu version to os name in releases", func() {
		cve := OvalCVE{URL: "some-url", Priority: "low"}
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
