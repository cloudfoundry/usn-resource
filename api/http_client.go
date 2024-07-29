package api

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net/http"

	"time"

	"github.com/andybalholm/brotli"
)

const acceptEncoding = "Accept-Encoding"
const uncompressedEncoding = "deflate"
const contentEncodingHeader = "Content-Encoding"
const brotliEncoding = "br"

func responseReaderAndStatus(url string) (io.Reader, int, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("unable to create request: %w", err)
	}
	req.Header.Set(acceptEncoding, uncompressedEncoding)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, 0, err
	}
	status := resp.StatusCode

	// Let's not let Canonical's server troubles ruin our day. Retry a few times on 5xx.
	for retryCount := 1; retryCount < 6; retryCount++ {
		if status < 500 || status > 599 {
			break
		} else {
			var sleepTime time.Duration = time.Duration(
				math.Min(math.Pow(1, float64(retryCount)), 4))
			time.Sleep(sleepTime * time.Second)

			resp, err = http.DefaultClient.Do(req)
			if err != nil {
				return nil, 0, err
			}
			status = resp.StatusCode
		}
	}

	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("http: error readomg resp.Body: %w", err)
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, 0, fmt.Errorf("http: error closing resp.Body: %w", err)
	}

	if resp.Header.Get(contentEncodingHeader) == brotliEncoding {
		responseBytes, err = io.ReadAll(brotli.NewReader(bytes.NewReader(responseBytes)))
		if err != nil {
			return nil, 0, fmt.Errorf("http: error decoding brotli response: %w", err)
		}
	}

	return bytes.NewReader(responseBytes), status, err
}
