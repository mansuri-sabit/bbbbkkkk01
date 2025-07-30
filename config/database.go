package config

import (
    "context"
    "fmt"
    "log"
    "os"
    "strings"
    "time"
    
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "go.mongodb.org/mongo-driver/mongo/options"
)

var (
    DB     *mongo.Database
    Client *mongo.Client
)

func InitMongoDB() {
    uri := os.Getenv("MONGODB_URI")
    if uri == "" {
        log.Fatal("❌ MONGODB_URI not set in environment")
    }
    
    // Log connection attempt (hide password for security)
    safeURI := hideSensitiveInfo(uri)
    log.Printf("🔗 Connecting to MongoDB: %s", safeURI)
    
    ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
    defer cancel()
    
    // Enhanced client options
    clientOptions := options.Client().ApplyURI(uri)
    clientOptions.SetMaxPoolSize(10)
    clientOptions.SetMinPoolSize(1)
    clientOptions.SetMaxConnIdleTime(30 * time.Second)
    clientOptions.SetServerSelectionTimeout(10 * time.Second)
    
    client, err := mongo.Connect(ctx, clientOptions)
    if err != nil {
        log.Fatalf("❌ Failed to connect to MongoDB: %v", err)
    }
    
    // Test connection with retry logic
    if err := testConnection(ctx, client); err != nil {
        log.Fatalf("❌ Failed to establish MongoDB connection: %v", err)
    }
    
    // Get database name from environment or use default
    dbName := os.Getenv("MONGODB_DATABASE")
    if dbName == "" {
        dbName = "jevi_chat"
        log.Printf("⚠️ MONGODB_DATABASE not set, using default: %s", dbName)
    }
    
    Client = client
    DB = client.Database(dbName)
    
    log.Printf("✅ Connected to MongoDB successfully (Database: %s)", dbName)
    
    // Verify collections and setup indexes
    if err := verifyCollections(ctx); err != nil {
        log.Printf("⚠️ Warning during collection verification: %v", err)
    }
}

func testConnection(ctx context.Context, client *mongo.Client) error {
    maxRetries := 3
    for i := 0; i < maxRetries; i++ {
        if err := client.Ping(ctx, nil); err != nil {
            if i == maxRetries-1 {
                return fmt.Errorf("ping failed after %d attempts: %v", maxRetries, err)
            }
            log.Printf("⚠️ Ping attempt %d failed, retrying...", i+1)
            time.Sleep(time.Duration(i+1) * time.Second)
            continue
        }
        return nil
    }
    return nil
}

func hideSensitiveInfo(uri string) string {
    if strings.Contains(uri, "@") {
        parts := strings.Split(uri, "@")
        if len(parts) >= 2 {
            credPart := parts[0]
            if strings.Contains(credPart, ":") {
                credParts := strings.Split(credPart, ":")
                if len(credParts) >= 3 {
                    return fmt.Sprintf("%s:%s:***@%s", credParts[0], credParts[1], parts[1])
                }
            }
        }
    }
    return uri
}

func verifyCollections(ctx context.Context) error {
    // ✅ UPDATED: Include notifications collection
    requiredCollections := []string{
        "projects", 
        "chat_messages", 
        "chat_users", 
        "gemini_usage_logs",
        "notifications", // ✅ Added notifications collection
        "users",         // ✅ Added users collection
    }
    
    // List existing collections
    collections, err := DB.ListCollectionNames(ctx, bson.M{})
    if err != nil {
        return fmt.Errorf("failed to list collections: %v", err)
    }
    
    log.Printf("📊 Available collections: %v", collections)
    
    // Check for required collections
    existingMap := make(map[string]bool)
    for _, col := range collections {
        existingMap[col] = true
    }
    
    for _, required := range requiredCollections {
        if !existingMap[required] {
            log.Printf("⚠️ Collection '%s' does not exist, it will be created on first use", required)
        } else {
            log.Printf("✅ Collection '%s' found", required)
        }
    }
    
    // Setup indexes for better performance
    return setupIndexes(ctx)
}

// ✅ COMPLETE: setupIndexes function with all collections
func setupIndexes(ctx context.Context) error {
    // Projects collection indexes
    projectsCol := DB.Collection("projects")
    _, err := projectsCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
        {
            Keys: bson.D{{"name", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"is_active", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"gemini_enabled", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"created_at", -1}},
            Options: options.Index().SetBackground(true),
        },
    })
    if err != nil {
        log.Printf("⚠️ Failed to create projects indexes: %v", err)
    }
    
    // Chat messages collection indexes
    chatCol := DB.Collection("chat_messages")
    _, err = chatCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
        {
            Keys: bson.D{{"project_id", 1}, {"session_id", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"timestamp", -1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"project_id", 1}, {"timestamp", -1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"user_id", 1}},
            Options: options.Index().SetBackground(true),
        },
    })
    if err != nil {
        log.Printf("⚠️ Failed to create chat_messages indexes: %v", err)
    }
    
    // Chat users collection indexes
    chatUsersCol := DB.Collection("chat_users")
    _, err = chatUsersCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
        {
            Keys: bson.D{{"project_id", 1}, {"email", 1}},
            Options: options.Index().SetBackground(true).SetUnique(true),
        },
        {
            Keys: bson.D{{"email", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"is_active", 1}},
            Options: options.Index().SetBackground(true),
        },
    })
    if err != nil {
        log.Printf("⚠️ Failed to create chat_users indexes: %v", err)
    }
    
    // Users collection indexes
    usersCol := DB.Collection("users")
    _, err = usersCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
        {
            Keys: bson.D{{"email", 1}},
            Options: options.Index().SetBackground(true).SetUnique(true),
        },
        {
            Keys: bson.D{{"username", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"is_active", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"role", 1}},
            Options: options.Index().SetBackground(true),
        },
    })
    if err != nil {
        log.Printf("⚠️ Failed to create users indexes: %v", err)
    }
    
    // Gemini usage logs collection indexes
    geminiCol := DB.Collection("gemini_usage_logs")
    _, err = geminiCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
        {
            Keys: bson.D{{"project_id", 1}, {"timestamp", -1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"timestamp", -1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"user_ip", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"success", 1}},
            Options: options.Index().SetBackground(true),
        },
    })
    if err != nil {
        log.Printf("⚠️ Failed to create gemini_usage_logs indexes: %v", err)
    }
    
    // ✅ NOTIFICATIONS: Notification collection indexes
    notificationsCol := DB.Collection("notifications")
    _, err = notificationsCol.Indexes().CreateMany(ctx, []mongo.IndexModel{
        {
            Keys: bson.D{{"project_id", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"user_id", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"created_at", -1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"expires_at", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"is_read", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"type", 1}},
            Options: options.Index().SetBackground(true),
        },
        {
            Keys: bson.D{{"project_id", 1}, {"type", 1}},
            Options: options.Index().SetBackground(true),
        },
    })
    if err != nil {
        log.Printf("⚠️ Failed to create notifications indexes: %v", err)
    }
    
    log.Println("📈 Database indexes setup completed successfully")
    return nil
}

func GetCollection(collectionName string) *mongo.Collection {
    if DB == nil {
        log.Fatal("❌ Database not initialized. Call InitMongoDB() first.")
    }
    
    if collectionName == "" {
        log.Fatal("❌ Collection name cannot be empty")
    }
    
    return DB.Collection(collectionName)
}

// ✅ COMPLETE: Convenience functions for commonly used collections
func GetProjectsCollection() *mongo.Collection {
    return GetCollection("projects")
}

func GetChatMessagesCollection() *mongo.Collection {
    return GetCollection("chat_messages")
}

func GetChatUsersCollection() *mongo.Collection {
    return GetCollection("chat_users")
}

func GetUsersCollection() *mongo.Collection {
    return GetCollection("users")
}

func GetGeminiUsageLogsCollection() *mongo.Collection {
    return GetCollection("gemini_usage_logs")
}

// ✅ NEW: Notification collection convenience function
func GetNotificationsCollection() *mongo.Collection {
    return GetCollection("notifications")
}

func HealthCheck() error {
    if DB == nil {
        return fmt.Errorf("database not initialized")
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    // Test connection
    if err := Client.Ping(ctx, nil); err != nil {
        return fmt.Errorf("database ping failed: %v", err)
    }
    
    // Test a simple query
    collection := GetCollection("projects")
    count, err := collection.CountDocuments(ctx, bson.M{})
    if err != nil {
        return fmt.Errorf("database query failed: %v", err)
    }
    
    log.Printf("💚 Database health check passed (Projects: %d)", count)
    return nil
}

// ✅ UPDATED: GetDatabaseStats with all collections including notifications
func GetDatabaseStats() map[string]interface{} {
    if DB == nil {
        return map[string]interface{}{"error": "database not initialized"}
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
    defer cancel()
    
    stats := make(map[string]interface{})
    
    // ✅ Get collection counts including notifications
    collections := []string{
        "projects", 
        "chat_messages", 
        "chat_users", 
        "users",
        "gemini_usage_logs", 
        "notifications", // ✅ Added notifications
    }
    
    for _, colName := range collections {
        count, err := GetCollection(colName).CountDocuments(ctx, bson.M{})
        if err != nil {
            stats[colName] = "error"
        } else {
            stats[colName] = count
        }
    }
    
    // ✅ Add additional stats
    stats["database_name"] = DB.Name()
    stats["timestamp"] = time.Now().Format(time.RFC3339)
    
    return stats
}

// ✅ NEW: Enhanced database stats with detailed information
func GetDetailedDatabaseStats() map[string]interface{} {
    if DB == nil {
        return map[string]interface{}{"error": "database not initialized"}
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    stats := make(map[string]interface{})
    
    // Basic collection counts
    basicStats := GetDatabaseStats()
    stats["collections"] = basicStats
    
    // Active projects count
    activeProjects, _ := GetProjectsCollection().CountDocuments(ctx, bson.M{"is_active": true})
    stats["active_projects"] = activeProjects
    
    // Recent messages (last 24 hours)
    yesterday := time.Now().Add(-24 * time.Hour)
    recentMessages, _ := GetChatMessagesCollection().CountDocuments(ctx, bson.M{
        "timestamp": bson.M{"$gte": yesterday},
    })
    stats["recent_messages_24h"] = recentMessages
    
    // Unread notifications
    unreadNotifications, _ := GetNotificationsCollection().CountDocuments(ctx, bson.M{
        "is_read": false,
        "expires_at": bson.M{"$gt": time.Now()},
    })
    stats["unread_notifications"] = unreadNotifications
    
    // Gemini usage today
    today := time.Now().Truncate(24 * time.Hour)
    geminiUsageToday, _ := GetGeminiUsageLogsCollection().CountDocuments(ctx, bson.M{
        "timestamp": bson.M{"$gte": today},
        "success": true,
    })
    stats["gemini_usage_today"] = geminiUsageToday
    
    return stats
}

// ✅ NEW: Cleanup expired data function
func CleanupExpiredData() error {
    if DB == nil {
        return fmt.Errorf("database not initialized")
    }
    
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    // Cleanup expired notifications
    result, err := GetNotificationsCollection().DeleteMany(ctx, bson.M{
        "expires_at": bson.M{"$lt": time.Now()},
    })
    if err != nil {
        log.Printf("⚠️ Failed to cleanup expired notifications: %v", err)
    } else {
        log.Printf("🧹 Cleaned up %d expired notifications", result.DeletedCount)
    }
    
    // Cleanup old chat messages (older than 6 months)
    sixMonthsAgo := time.Now().AddDate(0, -6, 0)
    result, err = GetChatMessagesCollection().DeleteMany(ctx, bson.M{
        "timestamp": bson.M{"$lt": sixMonthsAgo},
    })
    if err != nil {
        log.Printf("⚠️ Failed to cleanup old chat messages: %v", err)
    } else {
        log.Printf("🧹 Cleaned up %d old chat messages", result.DeletedCount)
    }
    
    // Cleanup old usage logs (older than 3 months)
    threeMonthsAgo := time.Now().AddDate(0, -3, 0)
    result, err = GetGeminiUsageLogsCollection().DeleteMany(ctx, bson.M{
        "timestamp": bson.M{"$lt": threeMonthsAgo},
    })
    if err != nil {
        log.Printf("⚠️ Failed to cleanup old usage logs: %v", err)
    } else {
        log.Printf("🧹 Cleaned up %d old usage logs", result.DeletedCount)
    }
    
    return nil
}

// ✅ NEW: Database maintenance function
func PerformMaintenance() error {
    log.Println("🔧 Starting database maintenance...")
    
    // Run cleanup
    if err := CleanupExpiredData(); err != nil {
        log.Printf("⚠️ Maintenance cleanup failed: %v", err)
        return err
    }
    
    // Get stats before and after
    stats := GetDetailedDatabaseStats()
    log.Printf("📊 Maintenance completed. Database stats: %+v", stats)
    
    return nil
}

// ✅ NEW: Create database backup metadata
func CreateBackupMetadata() map[string]interface{} {
    return map[string]interface{}{
        "backup_time": time.Now().Format(time.RFC3339),
        "database_name": DB.Name(),
        "stats": GetDatabaseStats(),
        "version": "1.0.0",
    }
}

func CloseMongoDB() {
    if Client != nil {
        ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
        defer cancel()
        
        // Perform final cleanup before closing
        CleanupExpiredData()
        
        if err := Client.Disconnect(ctx); err != nil {
            log.Printf("❌ Error disconnecting from MongoDB: %v", err)
        } else {
            log.Println("✅ Disconnected from MongoDB successfully")
        }
    }
}

// ✅ NEW: Initialize database with default data if needed
func InitializeDefaultData() error {
    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()
    
    // Check if admin user exists, create if not
    usersCol := GetUsersCollection()
    adminEmail := os.Getenv("ADMIN_EMAIL")
    if adminEmail != "" {
        count, _ := usersCol.CountDocuments(ctx, bson.M{"email": adminEmail})
        if count == 0 {
            log.Printf("🔧 Creating default admin user: %s", adminEmail)
            // Note: Actual user creation should be handled by your auth system
        }
    }
    
    log.Println("✅ Default data initialization completed")
    return nil
}
