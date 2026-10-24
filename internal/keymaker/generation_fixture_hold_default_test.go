//go:build linux && genjournal_testseam && !race

package keymaker

import gj "github.com/relux-works/swarma-user-manager/tools/genjournal"

const generationFixtureReaderHold = gj.ReaderHold
