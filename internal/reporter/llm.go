package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"

	"github.com/achyuta0001/tripwyre/internal/config"
	"github.com/achyuta0001/tripwyre/internal/finding"
)

const defaultModel = "claude-opus-4-8"

const synthesisSystemPrompt = `You are the synthesis engine of tripwyre, a project intelligence CLI that scans dependencies, config drift, and logs. You receive the processed findings of all scanners as JSON — never raw logs or raw config.

Write a brief synthesis for the project's maintainer:
1. Correlations: do findings from different scanners point at the same underlying incident or cause? Timestamps and values are evidence — cite them.
2. Priority: what to fix first, and why.
3. Next actions: 2-3 concrete steps.

Be specific and concise (under 250 words). If the findings look unrelated, say so in one sentence rather than forcing a connection.`

// LLMReporter renders the deterministic template report, then appends an
// LLM-written synthesis that correlates findings across scanners. It only
// ever receives processed Findings (including their Context excerpts) —
// never raw logs or config — so token cost stays bounded.
type LLMReporter struct {
	client anthropic.Client
	model  string
}

// NewLLMReporter builds the reporter from config. The API key is read from
// the env var named by cfg.APIKeyEnv (default ANTHROPIC_API_KEY); a missing
// key is an error at construction so users find out before scanning.
func NewLLMReporter(cfg config.ReporterConfig) (*LLMReporter, error) {
	keyEnv := cfg.APIKeyEnv
	if keyEnv == "" {
		keyEnv = "ANTHROPIC_API_KEY"
	}
	key := os.Getenv(keyEnv)
	if key == "" {
		return nil, fmt.Errorf("llm reporter: environment variable %s is not set (configure [reporter] api_key_env in tripwyre.toml or export the key)", keyEnv)
	}

	model := cfg.Model
	if model == "" {
		model = defaultModel
	}

	return &LLMReporter{
		client: anthropic.NewClient(option.WithAPIKey(key)),
		model:  model,
	}, nil
}

func (r *LLMReporter) Summarize(findings []finding.Finding) (string, error) {
	base, err := NewTemplateReporter().Summarize(findings)
	if err != nil {
		return "", err
	}
	if len(findings) == 0 {
		return base, nil
	}

	payload, err := json.Marshal(findings)
	if err != nil {
		return "", fmt.Errorf("llm reporter: encoding findings: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	resp, err := r.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(r.model),
		MaxTokens: 4096,
		System:    []anthropic.TextBlockParam{{Text: synthesisSystemPrompt}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(string(payload))),
		},
	})
	if err != nil {
		return "", fmt.Errorf("llm reporter: %w", err)
	}

	var sb strings.Builder
	for _, block := range resp.Content {
		if text, ok := block.AsAny().(anthropic.TextBlock); ok {
			sb.WriteString(text.Text)
		}
	}
	if sb.Len() == 0 {
		return "", fmt.Errorf("llm reporter: model returned no text (stop_reason: %s)", resp.StopReason)
	}

	return base + "\n── Synthesis ──\n\n" + sb.String() + "\n", nil
}
