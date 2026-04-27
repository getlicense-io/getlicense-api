package server

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/getlicense-io/getlicense-api/internal/server/middleware"
)

const redisRateLimitScript = `
local current = redis.call("INCR", KEYS[1])
if current == 1 then
	redis.call("PEXPIRE", KEYS[1], ARGV[2])
end

local ttl = redis.call("PTTL", KEYS[1])
if ttl < 0 then
	redis.call("PEXPIRE", KEYS[1], ARGV[2])
	ttl = tonumber(ARGV[2])
end

if current > tonumber(ARGV[1]) then
	return {0, ttl}
end
return {1, ttl}
`

type RedisRateLimiter struct {
	client redis.UniversalClient
	prefix string
	script *redis.Script
}

func NewRedisRateLimiter(client redis.UniversalClient, prefix string) middleware.RateLimiter {
	return &RedisRateLimiter{
		client: client,
		prefix: prefix,
		script: redis.NewScript(redisRateLimitScript),
	}
}

func (l *RedisRateLimiter) Hit(ctx context.Context, key string, limit int, window time.Duration) (bool, time.Duration, error) {
	windowMS := int64(window / time.Millisecond)
	if windowMS < 1 {
		windowMS = 1
	}

	result, err := l.script.Run(ctx, l.client, []string{l.prefix + key}, limit, windowMS).Result()
	if err != nil {
		return false, 0, err
	}

	parts, ok := result.([]interface{})
	if !ok || len(parts) != 2 {
		return false, 0, fmt.Errorf("unexpected Redis rate-limit result: %T", result)
	}

	allowed, err := redisInt(parts[0])
	if err != nil {
		return false, 0, err
	}
	retryAfterMS, err := redisInt(parts[1])
	if err != nil {
		return false, 0, err
	}
	if retryAfterMS < 0 {
		retryAfterMS = 0
	}

	return allowed == 1, time.Duration(retryAfterMS) * time.Millisecond, nil
}

func redisInt(v any) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case string:
		var out int64
		_, err := fmt.Sscan(n, &out)
		if err != nil {
			return 0, fmt.Errorf("unexpected Redis integer value %q: %w", n, err)
		}
		return out, nil
	default:
		return 0, fmt.Errorf("unexpected Redis integer type: %T", v)
	}
}
