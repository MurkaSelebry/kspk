package cat

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const apiURL = "https://api.thecatapi.com/v1/images/search"

// Service fetches random cats.
type Service struct {
	httpClient *http.Client
	apiKey     string
}

func NewService(client *http.Client, apiKey string) *Service {
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	return &Service{httpClient: client, apiKey: apiKey}
}

func (s *Service) FetchRandomCat(ctx context.Context) (int, []byte) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return http.StatusInternalServerError, []byte("{\"error\":\"build request\"}")
	}
	if s.apiKey != "" {
		req.Header.Set("x-api-key", s.apiKey)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return http.StatusBadGateway, []byte(fmt.Sprintf("{\"error\":\"\"}", err.Error()))
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return http.StatusBadGateway, []byte("{\"error\":\"read body\"}")
	}

	// Validate JSON shape a bit and re-emit
	var v []map[string]any
	if err := json.Unmarshal(body, &v); err != nil || len(v) == 0 {
		return http.StatusBadGateway, []byte("{\"error\":\"invalid response\"}")
	}
	return resp.StatusCode, body
}
