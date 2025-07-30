package config

import (
    "os"
    "strconv"
    "time"
)

type NotificationConfig struct {
    CleanupInterval     time.Duration
    DefaultExpiry       time.Duration
    MaxPerUser          int
    EnableCleanup       bool
    RateLimitPerMinute  int
    BurstLimit          int
    
    // Email settings
    SMTPHost            string
    SMTPPort            int
    SMTPUsername        string
    SMTPPassword        string
    SMTPFromEmail       string
    SMTPFromName        string
    
    // Webhook settings
    WebhookSecret       string
    SlackWebhookURL     string
    DiscordWebhookURL   string
}

var NotificationSettings *NotificationConfig

func InitNotificationConfig() {
    NotificationSettings = &NotificationConfig{
        CleanupInterval:     parseDuration("NOTIFICATION_CLEANUP_INTERVAL", "24h"),
        DefaultExpiry:       parseDuration("NOTIFICATION_DEFAULT_EXPIRY", "24h"),
        MaxPerUser:          parseInt("MAX_NOTIFICATIONS_PER_USER", 100),
        EnableCleanup:       parseBool("ENABLE_NOTIFICATION_CLEANUP", true),
        RateLimitPerMinute:  parseInt("NOTIFICATION_RATE_LIMIT_PER_MINUTE", 10),
        BurstLimit:          parseInt("NOTIFICATION_BURST_LIMIT", 20),
        
        // Email settings
        SMTPHost:            os.Getenv("SMTP_HOST"),
        SMTPPort:            parseInt("SMTP_PORT", 587),
        SMTPUsername:        os.Getenv("SMTP_USERNAME"),
        SMTPPassword:        os.Getenv("SMTP_PASSWORD"),
        SMTPFromEmail:       os.Getenv("SMTP_FROM_EMAIL"),
        SMTPFromName:        os.Getenv("SMTP_FROM_NAME"),
        
        // Webhook settings
        WebhookSecret:       os.Getenv("WEBHOOK_SECRET"),
        SlackWebhookURL:     os.Getenv("SLACK_WEBHOOK_URL"),
        DiscordWebhookURL:   os.Getenv("DISCORD_WEBHOOK_URL"),
    }
}

func parseDuration(key, defaultValue string) time.Duration {
    value := os.Getenv(key)
    if value == "" {
        value = defaultValue
    }
    duration, err := time.ParseDuration(value)
    if err != nil {
        duration, _ = time.ParseDuration(defaultValue)
    }
    return duration
}

func parseInt(key string, defaultValue int) int {
    value := os.Getenv(key)
    if value == "" {
        return defaultValue
    }
    intValue, err := strconv.Atoi(value)
    if err != nil {
        return defaultValue
    }
    return intValue
}

func parseBool(key string, defaultValue bool) bool {
    value := os.Getenv(key)
    if value == "" {
        return defaultValue
    }
    boolValue, err := strconv.ParseBool(value)
    if err != nil {
        return defaultValue
    }
    return boolValue
}
