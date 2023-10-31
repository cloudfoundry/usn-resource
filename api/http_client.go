package api

import (
	"fmt"
	"log"
	"net/http"
)

const acceptEncoding = "Accept-Encoding"
const uncompressedEncoding = "deflate"
const contentEncoding = "Content-Encoding"
const brotliEncoding = "br"
const maxAttempts = 5

func getNonBrotliResponse(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(acceptEncoding, uncompressedEncoding)

	var resp *http.Response
	i := 0
	for {
		log.Printf("http: fetch attempt %d '%s'", i, url)
		resp, err = http.DefaultClient.Do(req)
		if err != nil {
			return nil, err
		}
		i++

		if resp.Header.Get(contentEncoding) != brotliEncoding {
			break
		}
		if i > maxAttempts {
			log.Printf("http.Response.Headers: %+v", resp.Header)
			return nil, fmt.Errorf("failed to fetch non-brotli encoded response for '%s' after '%d' attempts", url, maxAttempts)
		}
	}
	return resp, err
}
