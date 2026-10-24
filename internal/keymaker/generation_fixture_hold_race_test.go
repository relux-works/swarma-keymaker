//go:build linux && genjournal_testseam && race

package keymaker

import "time"

// Instrumented capacity-vector verification needs more time; this does not
// qualify production latency or change writer fence budgets.
const generationFixtureReaderHold = 5 * time.Second
