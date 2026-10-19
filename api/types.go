package api

type Source struct {
	OS            string   `json:"os"`
	Priorities    []string `json:"priorities"`
	Severities    []string `json:"severities"`
	FetchAttempts int      `json:"fetch_attempts"`
}

// DefinitionFetchAttempts returns the configured `fetch_attempts`, or the
// package default when it is unset.
func (s Source) DefinitionFetchAttempts() int {
	if s.FetchAttempts == 0 {
		return DefinitionFetchAttempts
	}
	return s.FetchAttempts
}

type Version struct {
	GUID string `json:"guid"`
}

type Request struct {
	Source  Source  `json:"source"`
	Version Version `json:"version"`
}
