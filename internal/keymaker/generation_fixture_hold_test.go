//go:build linux

package keymaker

import "time"

// Semantic byte and tagged-source verdicts, including instrumented capacity
// vectors, get an explicit fixture budget in normal and race runs. Production
// and dedicated deadline tests retain 250ms; this is not a storage-latency qualification or a writer budget.
const generationFixtureReaderHold = 5 * time.Second
