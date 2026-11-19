package keymaker

import (
	"sync"
	"time"
)

type maLivePeerBudget struct{ all, sign bucket }
type maLiveBudget struct {
	mu     sync.Mutex
	global bucket
	peers  map[Principal]*maLivePeerBudget
	now    func() time.Time
}

func (b *maLiveBudget) charge(p Principal, sign bool) Code {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := time.Now()
	if b.now != nil {
		now = b.now()
	}
	if b.peers == nil {
		b.peers = map[Principal]*maLivePeerBudget{}
	}
	peer := b.peers[p]
	if peer == nil {
		if len(b.peers) >= 65536 {
			// An idle peer is reclaimable only after BOTH buckets have naturally
			// refilled. Resetting any outstanding debt would bypass its rate limit.
			for key, old := range b.peers {
				if maLiveBucketFull(old.all, now, 20, 40) && maLiveBucketFull(old.sign, now, 2, 4) {
					delete(b.peers, key)
				}
			}
			if len(b.peers) >= 65536 {
				return "rate_limited"
			}
		}
		peer = &maLivePeerBudget{}
		b.peers[p] = peer
	}
	if !b.global.take(now, 200, 256) || !peer.all.take(now, 20, 40) {
		return "rate_limited"
	}
	if sign && !peer.sign.take(now, 2, 4) {
		return "rate_limited"
	}
	return ""
}

// The Unix reader has already charged global/per-principal traffic, including
// malformed and busy requests. Recognizing sign adds only its dedicated bucket.
func (b *maLiveBudget) chargeSign(p Principal) Code {
	b.mu.Lock()
	defer b.mu.Unlock()
	peer := b.peers[p]
	if peer == nil {
		return "rate_limited"
	}
	now := time.Now()
	if b.now != nil {
		now = b.now()
	}
	if !peer.sign.take(now, 2, 4) {
		return "rate_limited"
	}
	return ""
}
func (h *maLiveHolder) chargeSign(p Principal) Code {
	h.mu.Lock()
	b := h.budget
	h.mu.Unlock()
	if b == nil {
		return "rate_limited"
	}
	return b.chargeSign(p)
}

func maLiveBucketFull(v bucket, now time.Time, rate, burst float64) bool {
	if v.last.IsZero() {
		return true
	}
	return now.After(v.last) && v.tokens+now.Sub(v.last).Seconds()*rate >= burst
}
