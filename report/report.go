package report

import (
	"encoding/json"
	"io"
	"time"

	"wdf/internal/scanner"
)

type Report struct {
	GeneratedAt time.Time              `json:"generated_at"`
	Config      scanner.Config         `json:"config"`
	Targets     []scanner.TargetResult `json:"targets"`
}

func WriteJSON(w io.Writer, r Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

