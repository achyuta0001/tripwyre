package deps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const osvBaseURL = "https://api.osv.dev"

// osvBatchLimit is OSV.dev's maximum queries per querybatch request.
const osvBatchLimit = 1000

// OSVClient implements VulnSource against the OSV.dev API.
// Strategy: one querybatch call per 1000 packages returns affected vuln
// IDs, then each unique ID is fetched once for severity and summary —
// so network cost scales with vulnerabilities found, not lockfile size.
type OSVClient struct {
	baseURL string
	http    *http.Client
}

func NewOSVClient(baseURL string) *OSVClient {
	if baseURL == "" {
		baseURL = osvBaseURL
	}
	return &OSVClient{
		baseURL: baseURL,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

type osvQuery struct {
	Package osvPackage `json:"package"`
	Version string     `json:"version"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type osvBatchResponse struct {
	Results []struct {
		Vulns []struct {
			ID string `json:"id"`
		} `json:"vulns"`
	} `json:"results"`
}

type osvVulnDetail struct {
	ID               string `json:"id"`
	Summary          string `json:"summary"`
	DatabaseSpecific struct {
		Severity string `json:"severity"`
	} `json:"database_specific"`
}

func (c *OSVClient) FindVulns(pkgs []Package) (map[Package][]Vuln, error) {
	if len(pkgs) == 0 {
		return nil, nil
	}

	idsByPkg := make(map[Package][]string)
	for start := 0; start < len(pkgs); start += osvBatchLimit {
		end := min(start+osvBatchLimit, len(pkgs))
		if err := c.queryBatch(pkgs[start:end], idsByPkg); err != nil {
			return nil, err
		}
	}

	details := make(map[string]Vuln)
	for _, ids := range idsByPkg {
		for _, id := range ids {
			if _, done := details[id]; done {
				continue
			}
			v, err := c.vulnDetail(id)
			if err != nil {
				return nil, err
			}
			details[id] = v
		}
	}

	result := make(map[Package][]Vuln, len(idsByPkg))
	for pkg, ids := range idsByPkg {
		for _, id := range ids {
			result[pkg] = append(result[pkg], details[id])
		}
	}
	return result, nil
}

func (c *OSVClient) queryBatch(pkgs []Package, idsByPkg map[Package][]string) error {
	queries := make([]osvQuery, len(pkgs))
	for i, p := range pkgs {
		queries[i] = osvQuery{
			Package: osvPackage{Name: p.Name, Ecosystem: p.Ecosystem},
			Version: p.Version,
		}
	}

	body, err := json.Marshal(map[string]any{"queries": queries})
	if err != nil {
		return err
	}

	resp, err := c.http.Post(c.baseURL+"/v1/querybatch", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("osv querybatch: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("osv querybatch: HTTP %d: %s", resp.StatusCode, msg)
	}

	var batch osvBatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&batch); err != nil {
		return fmt.Errorf("osv querybatch: decoding response: %w", err)
	}
	if len(batch.Results) != len(pkgs) {
		return fmt.Errorf("osv querybatch: got %d results for %d queries", len(batch.Results), len(pkgs))
	}

	for i, res := range batch.Results {
		for _, v := range res.Vulns {
			idsByPkg[pkgs[i]] = append(idsByPkg[pkgs[i]], v.ID)
		}
	}
	return nil
}

func (c *OSVClient) vulnDetail(id string) (Vuln, error) {
	resp, err := c.http.Get(c.baseURL + "/v1/vulns/" + id)
	if err != nil {
		return Vuln{}, fmt.Errorf("osv vuln %s: %w", id, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return Vuln{}, fmt.Errorf("osv vuln %s: HTTP %d: %s", id, resp.StatusCode, msg)
	}

	var d osvVulnDetail
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		return Vuln{}, fmt.Errorf("osv vuln %s: decoding response: %w", id, err)
	}

	return Vuln{ID: d.ID, Summary: d.Summary, Severity: d.DatabaseSpecific.Severity}, nil
}
