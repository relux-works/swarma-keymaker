//go:build linux && genjournal_testseam

package keymaker

import "time"

// Semantic verdicts, including instrumented capacity vectors, get an explicit
// fixture budget in all tagged runs. Production and dedicated deadline tests
// retain 250ms; this is not a storage-latency qualification or a writer budget.
const generationFixtureReaderHold = 5 * time.Second
