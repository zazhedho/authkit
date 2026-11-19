package shared

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// incrementScript bumps a counter and starts its window in one step, so a crash
// between INCR and EXPIRE cannot leave a counter that never expires. A counter
// found without an expiry is given one.
var incrementScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
local ttl = redis.call('PTTL', KEYS[1])
local window = tonumber(ARGV[1])
if ttl < 0 and window > 0 then
  redis.call('PEXPIRE', KEYS[1], window)
  ttl = window
end
return {count, ttl}
`)

// IncrementWithTTL bumps a rate counter atomically. The first increment starts
// the ttl window; the returned duration is what is left of it.
func IncrementWithTTL(ctx context.Context, client redis.Scripter, key string, ttl time.Duration) (int, time.Duration, error) {
	res, err := incrementScript.Run(ctx, client, []string{key}, ttl.Milliseconds()).Int64Slice()
	if err != nil {
		return 0, 0, err
	}
	if len(res) != 2 {
		return 0, 0, fmt.Errorf("increment %s: unexpected reply %v", key, res)
	}
	remaining := time.Duration(res[1]) * time.Millisecond
	if res[1] < 0 {
		remaining = 0
	}
	return int(res[0]), remaining, nil
}
