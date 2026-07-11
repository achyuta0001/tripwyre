package reporter

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/finding"
	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

func sampleFindings() []finding.Finding {
	return []finding.Finding{
		{
			Severity:  finding.Critical,
			Scanner:   finding.ScannerDeps,
			Title:     "lodash 4.17.20 — 5 CVEs (2 high, 3 moderate)",
			Detail:    map[string]any{"package": "lodash"},
			Context:   "GHSA-1: ReDoS in lodash trim functions",
			Timestamp: time.Date(2026, 7, 11, 12, 0, 0, 0, time.UTC),
		},
		{
			Severity: finding.Warning,
			Scanner:  finding.ScannerConfig,
			Title:    "DB_POOL_SIZE drifted in .env (expected: 10, observed: 3)",
		},
	}
}

// fakeMessagesAPI serves POST /v1/messages, captures the request body, and
// returns a fixed text response.
func fakeMessagesAPI(t *testing.T, replyText string, capturedBody *string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Errorf("unexpected path: %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if capturedBody != nil {
			*capturedBody = string(body)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"id":    "msg_test",
			"type":  "message",
			"role":  "assistant",
			"model": "claude-opus-4-8",
			"content": []map[string]any{
				{"type": "text", "text": replyText},
			},
			"stop_reason": "end_turn",
			"usage":       map[string]any{"input_tokens": 100, "output_tokens": 50},
		})
	}))
}

func testLLMReporter(srvURL string) *LLMReporter {
	return &LLMReporter{
		client: anthropic.NewClient(
			option.WithAPIKey("test-key"),
			option.WithBaseURL(srvURL),
			option.WithMaxRetries(0),
		),
		model: "claude-opus-4-8",
	}
}

func TestLLMSummarizeAppendsSynthesisToTemplateReport(t *testing.T) {
	var body string
	srv := fakeMessagesAPI(t, "The lodash CVEs and the pool-size drift are likely related.", &body)
	defer srv.Close()

	out, err := testLLMReporter(srv.URL).Summarize(sampleFindings())
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}

	// deterministic template report comes first, so users still see raw
	// findings even before reading the synthesis
	if !strings.Contains(out, "2 findings (1 critical, 1 warning, 0 info)") {
		t.Errorf("output missing template report:\n%s", out)
	}
	if !strings.Contains(out, "The lodash CVEs and the pool-size drift are likely related.") {
		t.Errorf("output missing LLM synthesis:\n%s", out)
	}

	// the model must receive processed findings — titles and Context — not raw files
	if !strings.Contains(body, "lodash 4.17.20") {
		t.Errorf("request body missing finding title:\n%s", body)
	}
	if !strings.Contains(body, "ReDoS in lodash trim functions") {
		t.Errorf("request body missing finding Context:\n%s", body)
	}
	if !strings.Contains(body, `"model":"claude-opus-4-8"`) {
		t.Errorf("request body missing model:\n%s", body)
	}
}

func TestLLMSummarizeEmptyFindingsSkipsAPI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("API must not be called for zero findings")
	}))
	defer srv.Close()

	out, err := testLLMReporter(srv.URL).Summarize(nil)
	if err != nil {
		t.Fatalf("Summarize() error = %v", err)
	}
	if !strings.Contains(out, "No findings") {
		t.Errorf("output = %q, want the all-clear message", out)
	}
}

func TestLLMSummarizeAPIErrorPropagates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, `{"type":"error","error":{"type":"api_error","message":"boom"}}`, http.StatusInternalServerError)
	}))
	defer srv.Close()

	if _, err := testLLMReporter(srv.URL).Summarize(sampleFindings()); err == nil {
		t.Fatal("Summarize() error = nil, want API error")
	}
}

func TestNewLLMReporterMissingKeyErrors(t *testing.T) {
	cfg := config.ReporterConfig{Backend: "llm", APIKeyEnv: "TRIPWYRE_TEST_MISSING_KEY"}
	_, err := NewLLMReporter(cfg)
	if err == nil {
		t.Fatal("NewLLMReporter() error = nil, want missing-key error")
	}
	if !strings.Contains(err.Error(), "TRIPWYRE_TEST_MISSING_KEY") {
		t.Errorf("error = %q, want it to name the env var", err)
	}
}

func TestNewLLMReporterDefaults(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "test-key")

	r, err := NewLLMReporter(config.ReporterConfig{Backend: "llm"})
	if err != nil {
		t.Fatalf("NewLLMReporter() error = %v", err)
	}
	if r.model != "claude-opus-4-8" {
		t.Errorf("default model = %q, want claude-opus-4-8", r.model)
	}
}
