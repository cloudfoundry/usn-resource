package api

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/google/brotli/go/cbrotli"
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
	responseBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, 0, fmt.Errorf("http: error readomg resp.Body: %w", err)
	}
	err = resp.Body.Close()
	if err != nil {
		return nil, 0, fmt.Errorf("http: error closing resp.Body: %w", err)
	}

	if resp.Header.Get(contentEncodingHeader) == brotliEncoding {
		responseBytes, err = cbrotli.Decode(responseBytes)
		if err != nil {
			return nil, 0, fmt.Errorf("http: error decoding brotli response: %w", err)
		}
	}

	return bytes.NewReader(responseBytes), status, err
}
