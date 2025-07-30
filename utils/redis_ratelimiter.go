package utils

import (
    "context"
    "errors"
   
    "github.com/go-redis/redis_rate/v10"
    "github.com/redis/go-redis/v9"
)

type RedisRateLimiter struct {
    client  *redis.Client
    limiter *redis_rate.Limiter
}

// NewRedisRateLimiter creates a new Redis-based rate limiter
func NewRedisRateLimiter(redisAddr, redisPassword string, redisDB int) *RedisRateLimiter {
    rdb := redis.NewClient(&redis.Options{
        Addr:     redisAddr,
        Password: redisPassword,
        DB:       redisDB,
    })
    
    return &RedisRateLimiter{
        client:  rdb,
        limiter: redis_rate.NewLimiter(rdb),
    }
}

// Allow checks if the request is allowed with Redis
func (rl *RedisRateLimiter) Allow(ctx context.Context, key string, limit redis_rate.Limit) (bool, error) {
    res, err := rl.limiter.Allow(ctx, key, limit)
    if err != nil {
        return false, err
    }
    
    if res.Remaining == 0 {
        return false, errors.New("rate limit exceeded")
    }
    
    return true, nil
}

// Close closes the Redis connection
func (rl *RedisRateLimiter) Close() error {
    return rl.client.Close()
}
