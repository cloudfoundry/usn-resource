package api

import (
	"compress/bzip2"
	xml2 "encoding/xml"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
)

type OvalCVE struct {
	URL      string `xml:"href,attr"`
	Priority string `xml:"priority,attr"`
}

type Issued struct {
	Date string `xml:"date,attr"`
}

type Advisory struct {
	CVEs   []OvalCVE `xml:"cve"`
	Issued Issued    `xml:"issued"`
}

func (a *Advisory) GetCVEUrls() []string {
	var urls []string
	for _, cve := range a.CVEs {
		urls = append(urls, cve.URL)
	}
	return urls
}

func (a *Advisory) GetCVEPriorities() []string {
	priorities := make(map[string]bool)
	for _, cve := range a.CVEs {
		priorities[cve.Priority] = true
	}
	keys := make([]string, 0, len(priorities))
	for k := range priorities {
		keys = append(keys, k)
	}
	return keys
}

type Reference struct {
	Source string `xml:"source,attr"`
	RefUrl string `xml:"ref_url,attr"`
}

type Metadata struct {
	Title       string      `xml:"title"`
	Description string      `xml:"description"`
	Advisory    Advisory    `xml:"advisory"`
	References  []Reference `xml:"reference"`
}

func (m *Metadata) GetUSNUrl() string {
	for _, ref := range m.References {
		if ref.Source == "USN" {
			return ref.RefUrl
		}
	}
	return ""
}

type Definition struct {
	Id       string   `xml:"id,attr"`
	Metadata Metadata `xml:"metadata"`
}

type OvalDefinitions struct {
	XMLName     xml2.Name    `xml:"oval_definitions"`
	Definitions []Definition `xml:"definitions>definition"`
}

type USNMetadata struct {
	URL         string   `json:"url"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Date        string   `json:"date"`
	Releases    []string `json:"releases"`
	Priorities  []string `json:"priorities"`
	CVEs        []string `json:"cves"`
}

func (d *Definition) ToUSNMetadata(osStr string) USNMetadata {
	return USNMetadata{
		URL:         d.Metadata.GetUSNUrl(),
		Title:       d.Metadata.Title,
		Description: d.Metadata.Description,
		Date:        d.Metadata.Advisory.Issued.Date,
		Releases:    []string{osStr},
		Priorities:  d.Metadata.Advisory.GetCVEPriorities(),
		CVEs:        d.Metadata.Advisory.GetCVEUrls(),
	}
}

func (od *OvalDefinitions) GetDefinition(id string) (Definition, error) {
	for i := len(od.Definitions) - 1; i >= 0; i-- {
		def := od.Definitions[i]
		if def.Id == id {
			return def, nil
		}
	}
	return Definition{}, errors.New(fmt.Sprintf("Unknown definition with id %s", id))
}

func ParseOvalData(xml []byte) (OvalDefinitions, error) {
	ovalDefinitions := OvalDefinitions{}
	err := xml2.Unmarshal(xml, &ovalDefinitions)
	if err != nil {
		return OvalDefinitions{}, err
	}
	return ovalDefinitions, nil
}

func GetOvalRawData(osStr string) ([]byte, error) {
	var lineToName = map[string]string{
		"ubuntu-14.04-lts": "trusty",
		"ubuntu-16.04-lts": "xenial",
		"ubuntu-18.04-lts": "bionic",
		"ubuntu-22.04-lts": "jammy",
		"ubuntu-24.04-lts": "noble",
	}

	val, ok := lineToName[osStr]
	if ok {
		osStr = val
	}

	url := fmt.Sprintf("https://security-metadata.canonical.com/oval/com.ubuntu.%s.usn.oval.xml.bz2", osStr)
	resp, err := http.Get(url)
	if err != nil {
		return []byte{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		return []byte{}, errors.New(fmt.Sprintf("Unknown os: %s", osStr))
	}
	defer resp.Body.Close()

	if resp.StatusCode > 299 {
		return []byte{}, errors.New(fmt.Sprintf("Unexpected error from server, status code: %d, url: %s", resp.StatusCode, url))
	}
	bz2Reader := bzip2.NewReader(resp.Body)
	decompressed, err := io.ReadAll(bz2Reader)
	if err != nil {
		log.Fatal(err)
	}
	return decompressed, nil
}
