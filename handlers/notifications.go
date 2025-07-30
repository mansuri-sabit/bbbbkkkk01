package handlers

import (
    "context"
    "fmt"
    "net/http"
    "time"

    "github.com/gin-gonic/gin"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
    "go.mongodb.org/mongo-driver/mongo/options"
    "jevi-chat/config"
    "jevi-chat/models"
)

// CreateNotification - Create a new notification
func CreateNotification(projectID primitive.ObjectID, userID primitive.ObjectID, notificationType, title, message string, metadata map[string]interface{}) error {
    // Use configured expiry time if available, otherwise default to 24 hours
    expiryTime := time.Now().Add(24 * time.Hour)
    if config.NotificationSettings != nil {
        expiryTime = time.Now().Add(config.NotificationSettings.DefaultExpiry)
    }

    notification := models.Notification{
        ProjectID: projectID,
        UserID:    userID,
        Type:      notificationType,
        Title:     title,
        Message:   message,
        IsRead:    false,
        CreatedAt: time.Now(),
        ExpiresAt: expiryTime,
        Metadata:  metadata,
    }

    collection := config.GetNotificationsCollection()
    _, err := collection.InsertOne(context.Background(), notification)
    if err != nil {
        fmt.Printf("Failed to create notification: %v\n", err)
        return err
    }

    return nil
}

// CreateLimitExpiredNotification - Specific function for limit expiry notifications
func CreateLimitExpiredNotification(projectID primitive.ObjectID, projectName string, limitType string, currentUsage, limit int) {
    metadata := map[string]interface{}{
        "limit_type":     limitType,
        "current_usage":  currentUsage,
        "limit":          limit,
        "project_name":   projectName,
        "severity":       "warning",
        "auto_generated": true,
        "timestamp":      time.Now().Unix(),
    }

    title := fmt.Sprintf("Usage Limit Reached - %s", projectName)
    message := "Your limit has expired."

    err := CreateNotification(
        projectID,
        primitive.NilObjectID, // System notification, no specific user
        models.NotificationTypeLimitExpired,
        title,
        message,
        metadata,
    )

    if err != nil {
        fmt.Printf("Failed to create limit expired notification: %v\n", err)
        return
    }

    // Optional: Send webhook notification
    go sendWebhookNotification(projectID, projectName, limitType, currentUsage, limit)
    
    fmt.Printf("✅ Limit expired notification created for project: %s (%s: %d/%d)\n", 
        projectName, limitType, currentUsage, limit)
}

// GetNotifications - Get notifications for admin/user
func GetNotifications(c *gin.Context) {
    // Check if user is admin or get user-specific notifications
    isAdmin := c.GetBool("is_admin")
    userID := c.GetString("user_id")

    collection := config.GetNotificationsCollection()
    
    // Build filter based on user role
    filter := bson.M{
        "expires_at": bson.M{"$gt": time.Now()}, // Only non-expired notifications
    }

    if !isAdmin && userID != "" {
        // Regular users only see their notifications
        userObjID, err := primitive.ObjectIDFromHex(userID)
        if err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
            return
        }
        filter["user_id"] = userObjID
    }

    // Get query parameters for filtering
    notificationType := c.Query("type")
    if notificationType != "" {
        filter["type"] = notificationType
    }

    projectID := c.Query("project_id")
    if projectID != "" {
        objID, err := primitive.ObjectIDFromHex(projectID)
        if err == nil {
            filter["project_id"] = objID
        }
    }

    // Sort by creation date (newest first) and limit to 50
    opts := options.Find().
        SetSort(bson.D{{"created_at", -1}}).
        SetLimit(50)

    cursor, err := collection.Find(context.Background(), filter, opts)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch notifications"})
        return
    }
    defer cursor.Close(context.Background())

    var notifications []models.Notification
    if err := cursor.All(context.Background(), &notifications); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse notifications"})
        return
    }

    // Count unread notifications
    unreadCount, _ := collection.CountDocuments(context.Background(), bson.M{
        "$and": []bson.M{
            filter,
            {"is_read": false},
        },
    })

    c.JSON(http.StatusOK, gin.H{
        "success":       true,
        "notifications": notifications,
        "count":         len(notifications),
        "unread_count":  unreadCount,
        "filter_applied": gin.H{
            "type":       notificationType,
            "project_id": projectID,
        },
    })
}

// MarkNotificationAsRead - Mark notification as read
func MarkNotificationAsRead(c *gin.Context) {
    notificationID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(notificationID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID"})
        return
    }

    collection := config.GetNotificationsCollection()
    result, err := collection.UpdateOne(
        context.Background(),
        bson.M{"_id": objID},
        bson.M{"$set": bson.M{"is_read": true}},
    )

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark notification as read"})
        return
    }

    if result.MatchedCount == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "Notification not found"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Notification marked as read",
    })
}

// MarkAllNotificationsAsRead - Mark all notifications as read for user
func MarkAllNotificationsAsRead(c *gin.Context) {
    isAdmin := c.GetBool("is_admin")
    userID := c.GetString("user_id")

    filter := bson.M{"is_read": false}
    
    if !isAdmin && userID != "" {
        userObjID, err := primitive.ObjectIDFromHex(userID)
        if err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
            return
        }
        filter["user_id"] = userObjID
    }

    collection := config.GetNotificationsCollection()
    result, err := collection.UpdateMany(
        context.Background(),
        filter,
        bson.M{"$set": bson.M{"is_read": true}},
    )

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to mark notifications as read"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "All notifications marked as read",
        "updated_count": result.ModifiedCount,
    })
}

// DeleteNotification - Delete a notification
func DeleteNotification(c *gin.Context) {
    notificationID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(notificationID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid notification ID"})
        return
    }

    collection := config.GetNotificationsCollection()
    result, err := collection.DeleteOne(context.Background(), bson.M{"_id": objID})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete notification"})
        return
    }

    if result.DeletedCount == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "Notification not found"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Notification deleted successfully",
    })
}

// GetNotificationStats - Get notification statistics for admin
func GetNotificationStats(c *gin.Context) {
    collection := config.GetNotificationsCollection()
    
    // Get total notifications
    totalCount, _ := collection.CountDocuments(context.Background(), bson.M{})
    
    // Get unread notifications
    unreadCount, _ := collection.CountDocuments(context.Background(), bson.M{"is_read": false})
    
    // Get active notifications (not expired)
    activeCount, _ := collection.CountDocuments(context.Background(), bson.M{
        "expires_at": bson.M{"$gt": time.Now()},
    })
    
    // Get notifications by type
    pipeline := []bson.M{
        {"$group": bson.M{
            "_id": "$type",
            "count": bson.M{"$sum": 1},
        }},
    }
    
    cursor, _ := collection.Aggregate(context.Background(), pipeline)
    var typeStats []bson.M
    cursor.All(context.Background(), &typeStats)
    
    // Get recent notifications (last 24 hours)
    yesterday := time.Now().Add(-24 * time.Hour)
    recentCount, _ := collection.CountDocuments(context.Background(), bson.M{
        "created_at": bson.M{"$gte": yesterday},
    })

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "stats": gin.H{
            "total_notifications":  totalCount,
            "unread_notifications": unreadCount,
            "active_notifications": activeCount,
            "recent_24h":          recentCount,
            "by_type":             typeStats,
        },
        "timestamp": time.Now().Format(time.RFC3339),
    })
}

// TestNotificationSystem - Test endpoint to verify notification system
func TestNotificationSystem(c *gin.Context) {
    // Create a test notification
    testProjectID := primitive.NewObjectID()
    
    CreateLimitExpiredNotification(
        testProjectID,
        "Test Project",
        "monthly",
        100,
        100,
    )
    
    config_info := gin.H{
        "default_expiry": "24h",
        "cleanup_enabled": true,
    }
    
    if config.NotificationSettings != nil {
        config_info = gin.H{
            "cleanup_interval": config.NotificationSettings.CleanupInterval.String(),
            "default_expiry":   config.NotificationSettings.DefaultExpiry.String(),
            "max_per_user":     config.NotificationSettings.MaxPerUser,
            "cleanup_enabled":  config.NotificationSettings.EnableCleanup,
        }
    }
    
    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Test notification created successfully",
        "test_project_id": testProjectID.Hex(),
        "config": config_info,
    })
}

// sendWebhookNotification - Optional webhook notification sender
func sendWebhookNotification(projectID primitive.ObjectID, projectName, limitType string, currentUsage, limit int) {
    // Skip if no webhook configuration
    if config.NotificationSettings == nil || config.NotificationSettings.SlackWebhookURL == "" {
        return
    }
    
    // Implement Slack webhook sending logic here
    // This is a placeholder for webhook integration
    fmt.Printf("📢 Webhook notification would be sent: Project %s reached %s limit (%d/%d)\n", 
        projectName, limitType, currentUsage, limit)
    
    // TODO: Implement actual webhook sending
    // You can add HTTP POST request to webhook URL here
}

// CleanupExpiredNotifications - Background task to clean up expired notifications
func CleanupExpiredNotifications() error {
    collection := config.GetNotificationsCollection()
    
    result, err := collection.DeleteMany(
        context.Background(),
        bson.M{"expires_at": bson.M{"$lt": time.Now()}},
    )
    
    if err != nil {
        fmt.Printf("Failed to cleanup expired notifications: %v\n", err)
        return err
    }
    
    if result.DeletedCount > 0 {
        fmt.Printf("🧹 Cleaned up %d expired notifications\n", result.DeletedCount)
    }
    
    return nil
}

// GetProjectNotifications - Get notifications for a specific project
func GetProjectNotifications(c *gin.Context) {
    projectID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }

    collection := config.GetNotificationsCollection()
    
    filter := bson.M{
        "project_id": objID,
        "expires_at": bson.M{"$gt": time.Now()},
    }

    opts := options.Find().
        SetSort(bson.D{{"created_at", -1}}).
        SetLimit(20)

    cursor, err := collection.Find(context.Background(), filter, opts)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch project notifications"})
        return
    }
    defer cursor.Close(context.Background())

    var notifications []models.Notification
    if err := cursor.All(context.Background(), &notifications); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse notifications"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "project_id": projectID,
        "notifications": notifications,
        "count": len(notifications),
    })
}
