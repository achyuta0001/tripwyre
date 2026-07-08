package adapter

// RawRecord is an unprocessed record from a source.
// Each adapter converts source-specific data into RawRecords
// before the rules engine processes them.
type RawRecord struct {
	Source  string
	Type    string
	Payload map[string]any
	Raw     string
}

// Adapter is implemented by each source connector.
type Adapter interface {
	Name() string
	Collect() ([]RawRecord, error)
}
