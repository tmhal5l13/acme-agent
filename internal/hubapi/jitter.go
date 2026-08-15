package hubapi

import (
	"hash/fnv"
	"math"
	"time"
)

// jitterFor returns a stable, deterministic pseudo-random duration in
// [0, maxJitter) for a given spoke+cert — the same pair always gets the
// same offset (so a certificate's due status can't flip-flop between polls
// just because jitter re-rolled on every request), while different
// certificates spread across the window. See
// config.ACMEDefaultsConfig.RenewalJitter for why this exists.
func jitterFor(spokeID, certName string, maxJitter time.Duration) time.Duration {
	if maxJitter <= 0 {
		return 0
	}
	h := fnv.New64a()
	h.Write([]byte(spokeID + "/" + certName))
	fraction := float64(h.Sum64()) / float64(math.MaxUint64)
	return time.Duration(fraction * float64(maxJitter))
}
