package deps

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	npmRegistryURL    = "https://registry.npmjs.org"
	pypiRegistryURL   = "https://pypi.org"
	cratesRegistryURL = "https://crates.io"

	// crates.io rejects requests without an identifying User-Agent.
	registryUserAgent = "tripwyre (dependency staleness check)"
)

// RegistryClient implements PublishSource against the public package
// registries. One GET per unique package — which is why the staleness
// rule is opt-in via staleness_days > 0.
type RegistryClient struct {
	npmURL    string
	pypiURL   string
	cratesURL string
	http      *http.Client
}

func NewRegistryClient() *RegistryClient {
	return &RegistryClient{
		npmURL:    npmRegistryURL,
		pypiURL:   pypiRegistryURL,
		cratesURL: cratesRegistryURL,
		http:      &http.Client{Timeout: 15 * time.Second},
	}
}

// LastPublish returns the most recent publish time for the package, or
// the zero time for ecosystems this client doesn't know how to query.
func (c *RegistryClient) LastPublish(pkg Package) (time.Time, error) {
	switch pkg.Ecosystem {
	case "npm":
		return c.npmLastPublish(pkg.Name)
	case "PyPI":
		return c.pypiLastPublish(pkg.Name)
	case "crates.io":
		return c.cratesLastPublish(pkg.Name)
	default:
		return time.Time{}, nil
	}
}

func (c *RegistryClient) npmLastPublish(name string) (time.Time, error) {
	// The abbreviated metadata document carries "modified": the time of
	// the last publish (or metadata change) — good enough for staleness.
	var doc struct {
		Modified time.Time `json:"modified"`
	}
	if err := c.getJSON(c.npmURL+"/"+name, "application/vnd.npm.install-v1+json", &doc); err != nil {
		return time.Time{}, fmt.Errorf("npm registry %s: %w", name, err)
	}
	return doc.Modified, nil
}

func (c *RegistryClient) pypiLastPublish(name string) (time.Time, error) {
	// /pypi/{name}/json "urls" lists the files of the latest release;
	// the newest upload time among them is the last publish.
	var doc struct {
		URLs []struct {
			UploadTime time.Time `json:"upload_time_iso_8601"`
		} `json:"urls"`
	}
	if err := c.getJSON(c.pypiURL+"/pypi/"+name+"/json", "", &doc); err != nil {
		return time.Time{}, fmt.Errorf("pypi %s: %w", name, err)
	}
	var last time.Time
	for _, u := range doc.URLs {
		if u.UploadTime.After(last) {
			last = u.UploadTime
		}
	}
	return last, nil
}

func (c *RegistryClient) cratesLastPublish(name string) (time.Time, error) {
	var doc struct {
		Crate struct {
			UpdatedAt time.Time `json:"updated_at"`
		} `json:"crate"`
	}
	if err := c.getJSON(c.cratesURL+"/api/v1/crates/"+name, "", &doc); err != nil {
		return time.Time{}, fmt.Errorf("crates.io %s: %w", name, err)
	}
	return doc.Crate.UpdatedAt, nil
}

func (c *RegistryClient) getJSON(url, accept string, out any) error {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", registryUserAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, msg)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
