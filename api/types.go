package api

type Source struct {
	OS         string   `json:"os"`
	Priorities []string `json:"priorities"`
	Severities []string `json:"severities"`
}

type Version struct {
	GUID string `json:"guid"`
}

type Request struct {
	Source  Source  `json:"source"`
	Version Version `json:"version"`
}
