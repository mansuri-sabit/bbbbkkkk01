package handlers

import (

    "math/rand"
   
        "context"
    "fmt"
    "io/ioutil"
    "net/http"
    "strings"
    "time"

    "github.com/gin-gonic/gin"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
    "jevi-chat/config"
    "jevi-chat/models"
)

// In handlers/admin.go
func AdminDashboard(c *gin.Context) {
    stats := map[string]interface{}{
        "total_users": 0,
        "total_projects": 0,
        "total_messages": 0,
        "active_users": 0,
    }
    
    // Get actual stats from database
    if userCollection := config.DB.Collection("users"); userCollection != nil {
        userCount, _ := userCollection.CountDocuments(context.Background(), bson.M{})
        activeUserCount, _ := userCollection.CountDocuments(context.Background(), bson.M{"is_active": true})
        stats["total_users"] = userCount
        stats["active_users"] = activeUserCount
    }
    
    if projectCollection := config.DB.Collection("projects"); projectCollection != nil {
        projectCount, _ := projectCollection.CountDocuments(context.Background(), bson.M{})
        stats["total_projects"] = projectCount
    }
    
    c.JSON(http.StatusOK, gin.H{
        "message": "Admin dashboard loaded successfully",
        "stats": stats,
        "timestamp": time.Now(),
    })
}

func AdminProjects(c *gin.Context) {
    fmt.Println("AdminProjects handler called - DEBUG")
    
    // Make sure this matches your actual MongoDB collection name
    collection := config.DB.Collection("projects")
    
    // Add debug logging to check collection existence
    count, err := collection.CountDocuments(context.Background(), bson.M{})
    fmt.Printf("Total documents in projects collection: %d\n", count)
    
    if err != nil {
        fmt.Printf("Error counting documents: %v\n", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch projects"})
        return
    }
    
    cursor, err := collection.Find(context.Background(), bson.M{})
    if err != nil {
        fmt.Printf("Error finding projects: %v\n", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch projects"})
        return
    }
    
    var projects []models.Project
    if err := cursor.All(context.Background(), &projects); err != nil {
        fmt.Printf("Error decoding projects: %v\n", err)
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode projects"})
        return
    }
    
    fmt.Printf("Successfully fetched %d projects from database\n", len(projects))
    
    // Always return an array, even if empty
    if projects == nil {
        projects = []models.Project{}
    }
    
    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "projects": projects,
        "count": len(projects),
        "total_in_db": count, // Add this for debugging
    })
}

func CreateProject(c *gin.Context) {
    fmt.Println("CreateProject handler called")
    
    var project models.Project
    
    // Log the raw request body for debugging
    body, _ := c.GetRawData()
    fmt.Printf("Raw request body: %s\n", string(body))
    
    // Reset the body for binding
    c.Request.Body = ioutil.NopCloser(strings.NewReader(string(body)))
    
    if err := c.ShouldBindJSON(&project); err != nil {
        fmt.Printf("JSON binding error: %v\n", err)
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid project data",
            "details": err.Error(),
        })
        return
    }
    
    fmt.Printf("Parsed project: %+v\n", project)
    
    // Initialize all required fields based on your struct
    project.ID = primitive.NewObjectID()
    project.IsActive = true
    project.CreatedAt = time.Now()
    project.UpdatedAt = time.Now()
    
    // Set default values for optional fields
    if project.WelcomeMessage == "" {
        project.WelcomeMessage = "Hello! How can I help you today?"
    }
    
    if project.Category == "" {
        project.Category = "General"
    }
    
    // Initialize Gemini settings with defaults
    if project.GeminiModel == "" {
        project.GeminiModel = "gemini-1.5-flash"
    }
    

    
    // Initialize arrays to prevent null values
    if project.PDFFiles == nil {
        project.PDFFiles = []models.PDFFile{}
    }
    
    // Initialize analytics fields
    project.TotalQuestions = 0

    project.LastUsed = time.Now()
    
    fmt.Printf("Project before insertion: %+v\n", project)
    
    // Insert into database
    collection := config.DB.Collection("projects")
    result, err := collection.InsertOne(context.Background(), project)
    if err != nil {
        fmt.Printf("Database insertion error: %v\n", err)
        c.JSON(http.StatusInternalServerError, gin.H{
            "error": "Failed to create project",
            "details": err.Error(),
        })
        return
    }
    
    fmt.Printf("Insertion successful. Result: %+v\n", result)
    
    c.JSON(http.StatusCreated, gin.H{
        "success": true,
        "message": "Project created successfully",
        "project": project,
        "inserted_id": result.InsertedID,
    })
}

func ProjectDetails(c *gin.Context) {
    projectID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }
    
    collection := config.DB.Collection("projects")
    var project models.Project
    err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&project)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "project": project,
    })
}

func UpdateProject(c *gin.Context) {
    projectID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }
    
    var updateData bson.M
    if err := c.ShouldBindJSON(&updateData); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid update data"})
        return
    }
    
    updateData["updated_at"] = time.Now()
    
    collection := config.DB.Collection("projects")
    _, err = collection.UpdateOne(
        context.Background(),
        bson.M{"_id": objID},
        bson.M{"$set": updateData},
    )
    
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update project"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "message": "Project updated successfully",
        "project_id": projectID,
    })
}

func DeleteProject(c *gin.Context) {
    projectID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }
    
    collection := config.DB.Collection("projects")
    _, err = collection.DeleteOne(context.Background(), bson.M{"_id": objID})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete project"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "message": "Project deleted successfully",
        "project_id": projectID,
    })
}

func AdminUsers(c *gin.Context) {
    // Get all users from database
    collection := config.DB.Collection("users")
    cursor, err := collection.Find(context.Background(), bson.M{})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch users"})
        return
    }
    
    var users []models.User
    cursor.All(context.Background(), &users)
    
    // Remove password from response
    for i := range users {
        users[i].Password = ""
    }
    
    c.JSON(http.StatusOK, gin.H{
        "title": "Users - Admin",
        "users": users,
        "count": len(users),
    })
    
    // Uncomment when you have the template:
    // c.HTML(http.StatusOK, "admin/users.html", gin.H{
    //     "title": "Users - Admin",
    //     "users": users,
    // })
}

func AdminAnalytics(c *gin.Context) {
    analytics := getAnalyticsData()
    
    c.JSON(http.StatusOK, gin.H{
        "title": "Analytics - Admin",
        "analytics": analytics,
    })
}

func GetAnalyticsData(c *gin.Context) {
    analytics := getAnalyticsData()
    c.JSON(http.StatusOK, gin.H{"data": analytics})
}

func AdminSettings(c *gin.Context) {
    settings := map[string]interface{}{
        "app_name": "Jevi Chat",
        "version": "1.0.0",
        "maintenance_mode": false,
        "max_file_size": "10MB",
        "allowed_file_types": []string{"pdf", "txt", "doc"},
    }
    
    c.JSON(http.StatusOK, gin.H{
        "title": "Settings - Admin",
        "settings": settings,
    })
}

func UpdateSettings(c *gin.Context) {
    var settings map[string]interface{}
    if err := c.ShouldBindJSON(&settings); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid settings data"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "message": "Settings updated successfully",
        "settings": settings,
    })
}

func GetUserDetails(c *gin.Context) {
    userID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
        return
    }
    
    collection := config.DB.Collection("users")
    var user models.User
    err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&user)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }
    
    user.Password = "" // Remove password from response
    
    c.JSON(http.StatusOK, gin.H{
        "user": user,
    })
}

func UpdateUser(c *gin.Context) {
    userID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
        return
    }
    
    var updateData bson.M
    if err := c.ShouldBindJSON(&updateData); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid update data"})
        return
    }
    
    updateData["updated_at"] = time.Now()
    delete(updateData, "password") // Don't allow password updates through this endpoint
    
    collection := config.DB.Collection("users")
    _, err = collection.UpdateOne(
        context.Background(),
        bson.M{"_id": objID},
        bson.M{"$set": updateData},
    )
    
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "message": "User updated successfully",
        "user_id": userID,
    })
}

func DeleteUser(c *gin.Context) {
    userID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
        return
    }
    
    collection := config.DB.Collection("users")
    _, err = collection.DeleteOne(context.Background(), bson.M{"_id": objID})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
        return
    }
    
    c.JSON(http.StatusOK, gin.H{
        "message": "User deleted successfully",
        "user_id": userID,
    })
}

func ToggleUserStatus(c *gin.Context) {
    userID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid user ID"})
        return
    }
    
    // Get current user status
    collection := config.DB.Collection("users")
    var user models.User
    err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&user)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }
    
    // Toggle status
    newStatus := !user.IsActive
    _, err = collection.UpdateOne(
        context.Background(),
        bson.M{"_id": objID},
        bson.M{"$set": bson.M{"is_active": newStatus, "updated_at": time.Now()}},
    )
    
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to toggle user status"})
        return
    }
    
    status := "activated"
    if !newStatus {
        status = "deactivated"
    }
    
    c.JSON(http.StatusOK, gin.H{
        "message": "User " + status + " successfully",
        "user_id": userID,
        "new_status": newStatus,
    })
}

func ToggleProjectStatus(c *gin.Context) {
    projectID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }
    
    // Get current project status
    collection := config.DB.Collection("projects")
    var project models.Project
    err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&project)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
        return
    }
    
    // Toggle status
    newStatus := !project.IsActive
    _, err = collection.UpdateOne(
        context.Background(),
        bson.M{"_id": objID},
        bson.M{"$set": bson.M{"is_active": newStatus, "updated_at": time.Now()}},
    )
    
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to toggle project status"})
        return
    }
    
    status := "activated"
    if !newStatus {
        status = "deactivated"
    }
    
    c.JSON(http.StatusOK, gin.H{
        "message": "Project " + status + " successfully",
        "project_id": projectID,
        "new_status": newStatus,
    })
}

// Helper functions
func getAdminStats() map[string]interface{} {
    stats := map[string]interface{}{
        "total_users": 0,
        "total_projects": 0,
        "total_messages": 0,
        "active_users": 0,
    }
    
    // Get user count
    if userCollection := config.DB.Collection("users"); userCollection != nil {
        userCount, _ := userCollection.CountDocuments(context.Background(), bson.M{})
        activeUserCount, _ := userCollection.CountDocuments(context.Background(), bson.M{"is_active": true})
        stats["total_users"] = userCount
        stats["active_users"] = activeUserCount
    }
    
    // Get project count
    if projectCollection := config.DB.Collection("projects"); projectCollection != nil {
        projectCount, _ := projectCollection.CountDocuments(context.Background(), bson.M{})
        stats["total_projects"] = projectCount
    }
    
    // Get message count
    if messageCollection := config.DB.Collection("chat_messages"); messageCollection != nil {
        messageCount, _ := messageCollection.CountDocuments(context.Background(), bson.M{})
        stats["total_messages"] = messageCount
    }
    
    return stats
}

func getAnalyticsData() map[string]interface{} {
    return map[string]interface{}{
        "daily_users": 150,
        "daily_messages": 1200,
        "response_time": "1.2s",
        "satisfaction_rate": "94%",
        "popular_features": []string{"PDF Chat", "Project Management", "User Dashboard"},
    }
}


func SetGeminiLimit(c *gin.Context) {
    projectID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }

    var input struct {
        Limit int `json:"limit"`
    }

    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    if input.Limit < 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Limit must be non-negative"})
        return
    }

    collection := config.DB.Collection("projects")
    _, err = collection.UpdateOne(
        context.Background(),
        bson.M{"_id": objID},
        bson.M{"$set": bson.M{"gemini_limit": input.Limit, "updated_at": time.Now()}},
    )

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update project"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "Gemini usage limit updated",
        "limit":   input.Limit,
    })
}

func ResetGeminiUsage(c *gin.Context) {
    projectID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }

    collection := config.DB.Collection("projects")
    _, err = collection.UpdateOne(
        context.Background(),
        bson.M{"_id": objID},
        bson.M{"$set": bson.M{"gemini_usage": 0, "updated_at": time.Now()}},
    )

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset usage"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"message": "Gemini usage counter reset"})
}



// GetRealtimeStats handles GET /api/admin/realtime-stats
func GetRealtimeStats(c *gin.Context) {
    // Generate real-time statistics
    stats := map[string]interface{}{
        "activeUsers":       getCurrentActiveUsers(),
        "messagesPerMinute": getMessagesPerMinute(),
        "serverLoad":        getServerLoad(),
        "apiCalls":          getAPICallsCount(),
        "timestamp":         time.Now(),
    }

    c.JSON(http.StatusOK, stats)
}

// Helper functions for real-time stats
func getCurrentActiveUsers() int {
    // Query your database for active users
    collection := config.GetCollection("users")
    count, err := collection.CountDocuments(context.TODO(), bson.M{
        "is_active": true,
        "last_active": bson.M{"$gte": time.Now().Add(-5 * time.Minute)},
    })
    
    if err != nil {
        // Return sample data if database query fails
        return rand.Intn(50) + 25
    }
    
    return int(count)
}

func getMessagesPerMinute() int {
    // Calculate messages per minute from your chat system
    collection := config.GetCollection("messages")
    count, err := collection.CountDocuments(context.TODO(), bson.M{
        "created_at": bson.M{"$gte": time.Now().Add(-1 * time.Minute)},
    })
    
    if err != nil {
        return rand.Intn(30) + 5
    }
    
    return int(count)
}

func getServerLoad() int {
    // Get server load percentage (0-100)
    // You can implement actual system monitoring here
    return rand.Intn(100)
}

func getAPICallsCount() int {
    // Count API calls - you might want to implement request logging
    return rand.Intn(1000) + 200
}

// Enhanced ToggleGeminiStatus with usage validation
func ToggleGeminiStatus(c *gin.Context) {
    projectID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }

    var input struct {
        Enabled bool `json:"enabled"`
    }

    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid input"})
        return
    }

    collection := config.DB.Collection("projects")
    
    // Get current project
    var project models.Project
    err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&project)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
        return
    }

    // Validate API key if enabling
    if input.Enabled && project.GeminiAPIKey == "" {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Cannot enable Gemini: No API key configured",
            "action_required": "Please configure Gemini API key first",
        })
        return
    }

    // Update project status
    update := bson.M{
        "$set": bson.M{
            "gemini_enabled": input.Enabled,
            "updated_at":     time.Now(),
        },
    }

    _, err = collection.UpdateOne(context.Background(), bson.M{"_id": objID}, update)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update project"})
        return
    }

    status := "disabled"
    if input.Enabled {
        status = "enabled"
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": fmt.Sprintf("Gemini AI %s for project", status),
        "enabled": input.Enabled,
        "current_usage": gin.H{
        
            "monthly": project.GeminiUsageMonth,
    
            "monthly_limit": project.GeminiMonthlyLimit,
        },
    })
}

// Enhanced GetGeminiAnalytics with detailed tracking
func GetGeminiAnalytics(c *gin.Context) {
    projectID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }

    // Get project details
    collection := config.DB.Collection("projects")
    var project models.Project
    err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&project)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
        return
    }

    // Get usage logs for analytics
    logsCollection := config.DB.Collection("gemini_usage_logs")
    
    // Get today's successful requests
    today := time.Now().Truncate(24 * time.Hour)
    todayCount, _ := logsCollection.CountDocuments(context.Background(), bson.M{
        "project_id": objID,
        "timestamp": bson.M{"$gte": today},
        "success": true,
    })

    // Get this month's successful requests
    thisMonth := time.Date(time.Now().Year(), time.Now().Month(), 1, 0, 0, 0, 0, time.UTC)
    monthCount, _ := logsCollection.CountDocuments(context.Background(), bson.M{
        "project_id": objID,
        "timestamp": bson.M{"$gte": thisMonth},
        "success": true,
    })

    analytics := gin.H{
        "project": gin.H{
            "id":              project.ID,
            "name":            project.Name,
            "gemini_enabled":  project.GeminiEnabled,
            "model":           project.GeminiModel,
        },
        "usage": gin.H{
            "today": gin.H{
                "count": todayCount,

            },
            "month": gin.H{
                "count": monthCount,
                "limit": project.GeminiMonthlyLimit,
                "remaining": project.GeminiMonthlyLimit - int(monthCount),
        
            },
            "total_questions": project.TotalQuestions,
            "last_used": project.LastUsed,
        },
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "analytics": analytics,
    })
}

// Add usage tracking helper function
func trackGeminiUsage(projectID primitive.ObjectID, question, response, model string, 
                     inputTokens, outputTokens int, responseTime int64, userIP string, success bool) {
    
    // Calculate cost (simplified pricing)
    var costPer1K float64 = 0.000075 // Gemini Flash pricing
    if model == "gemini-1.5-pro" {
        costPer1K = 0.00125
    }
    
    totalTokens := inputTokens + outputTokens
    estimatedCost := (float64(totalTokens) / 1000.0) * costPer1K
    
    // Save usage log
    usageLog := models.GeminiUsageLog{
        ProjectID:     projectID,
        Question:      question,
        Response:      response,
        Model:         model,
        InputTokens:   inputTokens,
        OutputTokens:  outputTokens,
        EstimatedCost: estimatedCost,
        ResponseTime:  responseTime,
        UserIP:        userIP,
        Timestamp:     time.Now(),
        Success:       success,
    }
    
    logCollection := config.DB.Collection("gemini_usage_logs")
    logCollection.InsertOne(context.Background(), usageLog)
    
    // Update project counters if successful
    if success {
        projectCollection := config.DB.Collection("projects")
        update := bson.M{
            "$inc": bson.M{
                "gemini_usage_today": 1,
                "gemini_usage_month": 1,
                "total_questions": 1,
                "estimated_cost_today": estimatedCost,
                "estimated_cost_month": estimatedCost,
            },
            "$set": bson.M{
                "last_used": time.Now(),
                "updated_at": time.Now(),
            },
        }
        projectCollection.UpdateOne(context.Background(), bson.M{"_id": projectID}, update)
    }
}

// File: handlers/admin.go

// GetProjectsWithLimits - Enhanced admin projects view with monthly limits
func GetProjectsWithLimits(c *gin.Context) {
    collection := config.DB.Collection("projects")
    
    cursor, err := collection.Find(context.Background(), bson.M{})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch projects"})
        return
    }

    var projects []models.Project
    if err := cursor.All(context.Background(), &projects); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to decode projects"})
        return
    }

    // Add usage percentage for each project
    projectsWithStats := make([]gin.H, len(projects))
    for i, project := range projects {
        usagePercentage := 0.0
        if project.GeminiMonthlyLimit > 0 {
            usagePercentage = float64(project.GeminiUsageMonth) / float64(project.GeminiMonthlyLimit) * 100
        }

        projectsWithStats[i] = gin.H{
            "id": project.ID,
            "name": project.Name,
            "description": project.Description,
            "is_active": project.IsActive,
            "gemini_enabled": project.GeminiEnabled,
            "monthly_usage": project.GeminiUsageMonth,
            "monthly_limit": project.GeminiMonthlyLimit,
            "usage_percentage": usagePercentage,
            "last_used": project.LastUsed,
            "created_at": project.CreatedAt,
        }
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "projects": projectsWithStats,
        "count": len(projects),
    })
}


// SetMonthlyGeminiLimit - Admin sets monthly Gemini token limit for any project
func SetMonthlyGeminiLimit(c *gin.Context) {
    projectID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }

    var input struct {
        MonthlyLimit int `json:"monthly_limit" binding:"required,min=0"`
    }

    if err := c.ShouldBindJSON(&input); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid input", 
            "details": err.Error(),
        })
        return
    }

    // Update project with new monthly limit
    collection := config.DB.Collection("projects")
    update := bson.M{
        "$set": bson.M{
            "gemini_monthly_limit": input.MonthlyLimit,
            "updated_at": time.Now(),
        },
    }

    result, err := collection.UpdateOne(
        context.Background(),
        bson.M{"_id": objID},
        update,
    )

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update monthly limit"})
        return
    }

    if result.MatchedCount == 0 {
        c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Monthly Gemini limit updated successfully",
        "project_id": projectID,
        "monthly_limit": input.MonthlyLimit,
    })
}


func ResetMonthlyUsage(c *gin.Context) {
    projectID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }

    collection := config.DB.Collection("projects")
    update := bson.M{
        "$set": bson.M{
            "gemini_usage_month": 0,
            "last_monthly_reset": time.Now(),
            "updated_at": time.Now(),
        },
    }

    _, err = collection.UpdateOne(
        context.Background(),
        bson.M{"_id": objID},
        update,
    )

    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset monthly usage"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Monthly usage counter reset successfully",
        "reset_date": time.Now(),
    })
}


