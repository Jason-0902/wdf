package scanner

import "context"

type IndexChecker interface {
	IsIndexed(ctx context.Context, target, path string) (bool, error)
}

// StubIndexChecker is a placeholder for future integrations (e.g., Custom Search APIs).
// It never reports a URL as indexed.
type StubIndexChecker struct{}

func (StubIndexChecker) IsIndexed(ctx context.Context, target, path string) (bool, error) {
	return false, nil
}

