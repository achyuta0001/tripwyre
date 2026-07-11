package deps

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRegistryLastPublishNPM(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/lodash" {
			t.Errorf("npm path = %q, want /lodash", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"name":"lodash","modified":"2021-02-20T15:42:16.891Z"}`))
	}))
	defer srv.Close()

	c := NewRegistryClient()
	c.npmURL = srv.URL

	got, err := c.LastPublish(Package{Ecosystem: "npm", Name: "lodash"})
	if err != nil {
		t.Fatalf("LastPublish() error = %v", err)
	}
	want := time.Date(2021, 2, 20, 15, 42, 16, 891000000, time.UTC)
	if !got.Equal(want) {
		t.Errorf("LastPublish() = %v, want %v", got, want)
	}
}

func TestRegistryLastPublishPyPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/pypi/requests/json" {
			t.Errorf("pypi path = %q, want /pypi/requests/json", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"urls":[
			{"upload_time_iso_8601":"2023-05-22T15:12:42.313790Z"},
			{"upload_time_iso_8601":"2023-05-22T15:12:44.175000Z"}
		]}`))
	}))
	defer srv.Close()

	c := NewRegistryClient()
	c.pypiURL = srv.URL

	got, err := c.LastPublish(Package{Ecosystem: "PyPI", Name: "requests"})
	if err != nil {
		t.Fatalf("LastPublish() error = %v", err)
	}
	// latest file upload time wins
	want := time.Date(2023, 5, 22, 15, 12, 44, 175000000, time.UTC)
	if !got.Equal(want) {
		t.Errorf("LastPublish() = %v, want %v", got, want)
	}
}

func TestRegistryLastPublishCrates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/crates/serde" {
			t.Errorf("crates path = %q, want /api/v1/crates/serde", r.URL.Path)
		}
		if r.Header.Get("User-Agent") == "" {
			t.Error("crates.io requires a User-Agent header")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"crate":{"updated_at":"2024-02-13T01:20:33.123456Z"}}`))
	}))
	defer srv.Close()

	c := NewRegistryClient()
	c.cratesURL = srv.URL

	got, err := c.LastPublish(Package{Ecosystem: "crates.io", Name: "serde"})
	if err != nil {
		t.Fatalf("LastPublish() error = %v", err)
	}
	want := time.Date(2024, 2, 13, 1, 20, 33, 123456000, time.UTC)
	if !got.Equal(want) {
		t.Errorf("LastPublish() = %v, want %v", got, want)
	}
}

func TestRegistryUnknownEcosystemReturnsZero(t *testing.T) {
	c := NewRegistryClient()
	got, err := c.LastPublish(Package{Ecosystem: "maven", Name: "x"})
	if err != nil {
		t.Fatalf("LastPublish() error = %v, unknown ecosystems must be skipped silently", err)
	}
	if !got.IsZero() {
		t.Errorf("LastPublish() = %v, want zero time for unsupported ecosystem", got)
	}
}

func TestRegistryHTTPErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	}))
	defer srv.Close()

	c := NewRegistryClient()
	c.npmURL = srv.URL

	if _, err := c.LastPublish(Package{Ecosystem: "npm", Name: "ghost"}); err == nil {
		t.Fatal("LastPublish() error = nil, want HTTP error")
	}
}
