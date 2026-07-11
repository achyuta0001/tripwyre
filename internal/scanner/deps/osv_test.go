package deps

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// fakeOSV serves /v1/querybatch and /v1/vulns/{id} like api.osv.dev.
func fakeOSV(t *testing.T, vulnIDsByPkg map[string][]string, detailCalls *atomic.Int64) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/querybatch":
			var req struct {
				Queries []struct {
					Package struct {
						Name      string `json:"name"`
						Ecosystem string `json:"ecosystem"`
					} `json:"package"`
					Version string `json:"version"`
				} `json:"queries"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Errorf("bad querybatch body: %v", err)
			}
			type vulnRef struct {
				ID string `json:"id"`
			}
			type result struct {
				Vulns []vulnRef `json:"vulns,omitempty"`
			}
			results := make([]result, len(req.Queries))
			for i, q := range req.Queries {
				key := q.Package.Name + "@" + q.Version
				for _, id := range vulnIDsByPkg[key] {
					results[i].Vulns = append(results[i].Vulns, vulnRef{ID: id})
				}
			}
			json.NewEncoder(w).Encode(map[string]any{"results": results})

		case strings.HasPrefix(r.URL.Path, "/v1/vulns/"):
			if detailCalls != nil {
				detailCalls.Add(1)
			}
			id := strings.TrimPrefix(r.URL.Path, "/v1/vulns/")
			json.NewEncoder(w).Encode(map[string]any{
				"id":      id,
				"summary": "summary of " + id,
				"database_specific": map[string]any{
					"severity": "HIGH",
				},
			})

		default:
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func TestOSVClientFindVulns(t *testing.T) {
	srv := fakeOSV(t, map[string][]string{
		"lodash@4.17.20": {"GHSA-AAA", "GHSA-BBB"},
	}, nil)
	defer srv.Close()

	c := NewOSVClient(srv.URL)
	lodash := Package{Ecosystem: "npm", Name: "lodash", Version: "4.17.20"}
	clean := Package{Ecosystem: "npm", Name: "clean-pkg", Version: "1.0.0"}

	got, err := c.FindVulns([]Package{lodash, clean})
	if err != nil {
		t.Fatalf("FindVulns() error = %v", err)
	}

	vulns := got[lodash]
	if len(vulns) != 2 {
		t.Fatalf("lodash vulns = %d, want 2: %+v", len(vulns), got)
	}
	if vulns[0].Severity != "HIGH" {
		t.Errorf("severity = %q, want HIGH from database_specific", vulns[0].Severity)
	}
	if !strings.Contains(vulns[0].Summary, "summary of") {
		t.Errorf("summary = %q, want detail summary", vulns[0].Summary)
	}
	if len(got[clean]) != 0 {
		t.Errorf("clean package should have no vulns, got %+v", got[clean])
	}
}

func TestOSVClientDedupsDetailFetches(t *testing.T) {
	var detailCalls atomic.Int64
	// same vuln ID affects both packages → detail must be fetched once
	srv := fakeOSV(t, map[string][]string{
		"a@1.0.0": {"GHSA-SHARED"},
		"b@2.0.0": {"GHSA-SHARED"},
	}, &detailCalls)
	defer srv.Close()

	c := NewOSVClient(srv.URL)
	_, err := c.FindVulns([]Package{
		{Ecosystem: "npm", Name: "a", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "b", Version: "2.0.0"},
	})
	if err != nil {
		t.Fatalf("FindVulns() error = %v", err)
	}
	if n := detailCalls.Load(); n != 1 {
		t.Errorf("detail fetches = %d, want 1 (dedup by vuln ID)", n)
	}
}

func TestOSVClientServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := NewOSVClient(srv.URL)
	_, err := c.FindVulns([]Package{{Ecosystem: "npm", Name: "x", Version: "1.0.0"}})
	if err == nil {
		t.Fatal("FindVulns() error = nil, want error on HTTP 500")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %q, want it to mention status", err)
	}
}

func TestOSVClientEmptyInput(t *testing.T) {
	c := NewOSVClient("http://invalid.invalid") // must not be contacted
	got, err := c.FindVulns(nil)
	if err != nil {
		t.Fatalf("FindVulns(nil) error = %v", err)
	}
	if len(got) != 0 {
		t.Errorf("FindVulns(nil) = %+v, want empty", got)
	}
}
