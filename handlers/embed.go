package handlers

import (
    "context"
    "crypto/rand"
    "encoding/hex"
    "fmt"
    "net/http"
    "os"
    "time"

    "github.com/gin-gonic/gin"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
    "golang.org/x/crypto/bcrypt"
    "jevi-chat/config"
    "jevi-chat/models"
)

// EmbedAuth handles both GET and POST for authentication
func EmbedAuth(c *gin.Context) {
    projectID := c.Param("projectId")
    
    // Validate project ID
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "message": "Invalid project ID",
        })
        return
    }

    // Verify project exists and is active
    projectCollection := config.DB.Collection("projects")
    var project models.Project
    err = projectCollection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&project)
    if err != nil || !project.IsActive {
        c.JSON(http.StatusNotFound, gin.H{
            "success": false,
            "message": "Project not found or inactive",
        })
        return
    }

    if c.Request.Method == "GET" {
        // Show auth form
        c.HTML(http.StatusOK, "embed/auth.html", gin.H{
            "project":    project,
            "project_id": projectID,
            "api_url":    os.Getenv("APP_URL"),
        })
        return
    }

    // Handle POST - Authentication
    var authData struct {
        Mode     string `json:"mode" binding:"required"`
        Name     string `json:"name"`
        Email    string `json:"email" binding:"required,email"`
        Password string `json:"password" binding:"required"`
    }

    if err := c.ShouldBindJSON(&authData); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "message": "Invalid request data",
            "error":   err.Error(),
        })
        return
    }

    // Validate mode
    if authData.Mode != "register" && authData.Mode != "login" {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "message": "Invalid mode. Must be 'register' or 'login'",
        })
        return
    }

    userCollection := config.DB.Collection("chat_users")

    if authData.Mode == "register" {
        // Registration logic
        var existingUser models.ChatUser
        err := userCollection.FindOne(context.Background(), bson.M{
            "project_id": projectID,
            "email":      authData.Email,
        }).Decode(&existingUser)
        
        if err == nil {
            c.JSON(http.StatusConflict, gin.H{
                "success": false,
                "message": "Email already registered for this project",
            })
            return
        }

        // Hash password properly
        hashedPassword, err := bcrypt.GenerateFromPassword([]byte(authData.Password), bcrypt.DefaultCost)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{
                "success": false,
                "message": "Failed to process password",
            })
            return
        }

        user := models.ChatUser{
            ProjectID: projectID,
            Name:      authData.Name,
            Email:     authData.Email,
            Password:  string(hashedPassword),
            IsActive:  true,
            CreatedAt: time.Now(),
        }

        result, err := userCollection.InsertOne(context.Background(), user)
        if err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{
                "success": false,
                "message": "Failed to create user",
            })
            return
        }

        user.ID = result.InsertedID.(primitive.ObjectID)
        token := generateUserToken(user.ID.Hex())

        c.JSON(http.StatusOK, gin.H{
            "success": true,
            "message": "Registration successful",
            "user": gin.H{
                "id":    user.ID.Hex(),
                "name":  user.Name,
                "email": user.Email,
            },
            "token": token,
        })
        return
    }

    // Login logic
    var user models.ChatUser
    err = userCollection.FindOne(context.Background(), bson.M{
        "project_id": projectID,
        "email":      authData.Email,
    }).Decode(&user)
    
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{
            "success": false,
            "message": "Invalid email or password",
        })
        return
    }

    // Verify password
    err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(authData.Password))
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{
            "success": false,
            "message": "Invalid email or password",
        })
        return
    }

    if !user.IsActive {
        c.JSON(http.StatusUnauthorized, gin.H{
            "success": false,
            "message": "Account is deactivated",
        })
        return
    }

    token := generateUserToken(user.ID.Hex())

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Login successful",
        "user": gin.H{
            "id":    user.ID.Hex(),
            "name":  user.Name,
            "email": user.Email,
        },
        "token": token,
    })
}

// EmbedChat handles the main embed interface
func EmbedChat(c *gin.Context) {
    projectID := c.Param("projectId")
    userToken := c.Query("token")

    // Validate project ID
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.HTML(http.StatusBadRequest, "error.html", gin.H{
            "error": "Invalid project ID",
        })
        return
    }

    // Get project details
    projectCollection := config.DB.Collection("projects")
    var project models.Project
    err = projectCollection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&project)
    if err != nil || !project.IsActive {
        c.HTML(http.StatusNotFound, "error.html", gin.H{
            "error": "Project not found or inactive",
        })
        return
    }

    // If no token, show pre-auth UI
    if userToken == "" {
        c.HTML(http.StatusOK, "embed/prechat.html", gin.H{
            "project":    project,
            "project_id": projectID,
            "api_url":    os.Getenv("APP_URL"),
        })
        return
    }

    // Validate token and get user
    userID, err := validateUserToken(userToken)
    if err != nil {
        // Redirect to auth if token is invalid
        c.Redirect(http.StatusFound, fmt.Sprintf("/embed/%s", projectID))
        return
    }

    // Get user details
    userCollection := config.DB.Collection("chat_users")
    var user models.ChatUser
    userObjID, _ := primitive.ObjectIDFromHex(userID)
    err = userCollection.FindOne(context.Background(), bson.M{"_id": userObjID}).Decode(&user)
    if err != nil {
        c.Redirect(http.StatusFound, fmt.Sprintf("/embed/%s", projectID))
        return
    }

    // Render chat interface
    c.HTML(http.StatusOK, "embed/chat.html", gin.H{
        "project":    project,
        "project_id": projectID,
        "api_url":    os.Getenv("APP_URL"),
        "user":       user,
        "user_token": userToken,
    })
}

// IframeChatInterface - For direct iframe embedding
func IframeChatInterface(c *gin.Context) {
    projectID := c.Param("projectId")
    
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "error": "Invalid project ID",
        })
        return
    }

    var project models.Project
    err = config.DB.Collection("projects").FindOne(context.Background(), bson.M{"_id": objID}).Decode(&project)
    if err != nil || !project.IsActive {
        c.JSON(http.StatusNotFound, gin.H{
            "error": "Project not found or inactive",
        })
        return
    }

    c.HTML(http.StatusOK, "embed/chat.html", gin.H{
        "project":    project,
        "project_id": project.ID.Hex(),
        "api_url":    os.Getenv("APP_URL"),
        "anonymous":  true, // Allow anonymous access for iframe
    })
}

// EmbedHealth - Health check for embed service
func EmbedHealth(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
        "status":    "healthy",
        "service":   "jevi-chat-embed",
        "timestamp": time.Now().Format(time.RFC3339),
        "cors":      "enabled",
    })
}

// Utility functions
func generateUserToken(userID string) string {
    bytes := make([]byte, 16)
    rand.Read(bytes)
    return fmt.Sprintf("%s_%s_%d", userID, hex.EncodeToString(bytes), time.Now().Unix())
}

func validateUserToken(token string) (string, error) {
    if len(token) < 24 {
        return "", fmt.Errorf("invalid token format")
    }
    
    userID := token[:24]
    _, err := primitive.ObjectIDFromHex(userID)
    if err != nil {
        return "", fmt.Errorf("invalid user ID in token")
    }
    
    return userID, nil
}
