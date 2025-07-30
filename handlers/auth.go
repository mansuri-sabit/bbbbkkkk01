package handlers

import (
    "context"
    "net/http"
    "os"
    "time"
    
    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v4"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
    "golang.org/x/crypto/bcrypt"
    "jevi-chat/config"
    "jevi-chat/models"
)

func RegisterPage(c *gin.Context) {
    c.HTML(http.StatusOK, "auth/register.html", gin.H{
        "title": "Register - Jevi Chat",
    })
}

func Register(c *gin.Context) {
    var user models.User
    var registerData struct {
        Username string `json:"username" form:"username"`
        Email    string `json:"email" form:"email"`
        Password string `json:"password" form:"password"`
    }
    
    // Bind JSON or form data
    if err := c.ShouldBind(&registerData); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request data"})
        return
    }
    
    user.Username = registerData.Username
    user.Email = registerData.Email
    
    // Hash password
    hashedPassword, err := bcrypt.GenerateFromPassword([]byte(registerData.Password), bcrypt.DefaultCost)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
        return
    }
    user.Password = string(hashedPassword)
    user.IsActive = true
    user.Role = "user"
    user.CreatedAt = time.Now()
    user.UpdatedAt = time.Now()
    
    // Check if user already exists
    collection := config.DB.Collection("users")
    var existingUser models.User
    err = collection.FindOne(context.Background(), bson.M{"email": user.Email}).Decode(&existingUser)
    if err == nil {
        c.JSON(http.StatusConflict, gin.H{"error": "User with this email already exists"})
        return
    }
    
    // Insert user
    result, err := collection.InsertOne(context.Background(), user)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
        return
    }
    
    user.ID = result.InsertedID.(primitive.ObjectID)
    
    // Generate JWT token
    token := generateJWT(user.ID.Hex(), false)
    
    c.SetCookie("token", token, 3600*24, "/", "", false, true)
    
    // Return JSON response for AJAX requests
    if c.GetHeader("Content-Type") == "application/json" {
        c.JSON(http.StatusOK, gin.H{
            "success": true,
            "message": "Registration successful",
            "redirect": "/user/dashboard",
        })
        return
    }
    
    c.Redirect(http.StatusFound, "/user/dashboard")
}


func Login(c *gin.Context) {
    var loginData struct {
        Email    string `json:"email" form:"email"`
        Password string `json:"password" form:"password"`
    }

    if err := c.ShouldBind(&loginData); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{
            "success": false,
            "error": "Invalid request data",
        })
        return
    }

    adminEmail := os.Getenv("ADMIN_EMAIL")
    adminPassword := os.Getenv("ADMIN_PASSWORD")

    if loginData.Email == adminEmail && loginData.Password == adminPassword {
        token := generateJWT("admin", true)
        c.SetCookie("token", token, 3600*24, "/", "", false, true)

        c.JSON(http.StatusOK, gin.H{
            "success": true,
            "message": "Admin login successful",
            "token": token,
            "redirect": "/admin/dashboard",
        })
        return
    }

    // ✅ Now handle regular user login
    var user models.User
    collection := config.DB.Collection("users")

    err := collection.FindOne(context.Background(), bson.M{"email": loginData.Email}).Decode(&user)
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{
            "success": false,
            "error": "User not found",
        })
        return
    }

    if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(loginData.Password)); err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{
            "success": false,
            "error": "Invalid credentials",
        })
        return
    }

    token := generateJWT(user.ID.Hex(), false)
    c.SetCookie("token", token, 3600*24, "/", "", false, true)

    c.JSON(http.StatusOK, gin.H{
        "success": true,
        "message": "Login successful",
        "token": token,
        "redirect": "/user/dashboard",
        "user": gin.H{
            "id": user.ID.Hex(),
            "username": user.Username,
            "email": user.Email,
        },
    })
}

func UserDashboard(c *gin.Context) {
    userID := c.GetString("user_id")
    
    // Get user details
    collection := config.DB.Collection("users")
    var user models.User
    objID, _ := primitive.ObjectIDFromHex(userID)
    err := collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&user)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
        return
    }
    
    // Get user's projects
    projectCollection := config.DB.Collection("projects")
    cursor, err := projectCollection.Find(context.Background(), bson.M{"user_id": objID})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch projects"})
        return
    }
    
    var projects []models.Project
    cursor.All(context.Background(), &projects)
    
    c.HTML(http.StatusOK, "user/dashboard.html", gin.H{
        "title": "User Dashboard - Jevi Chat",
        "user": user,
        "projects": projects,
    })
}

func Logout(c *gin.Context) {
    c.SetCookie("token", "", -1, "/", "", false, true)
    
    // Return JSON response for AJAX requests
    if c.GetHeader("Content-Type") == "application/json" || c.Query("format") == "json" {
        c.JSON(http.StatusOK, gin.H{
            "success": true,
            "message": "Logged out successfully",
            "redirect": "/login",
        })
        return
    }
    
    c.Redirect(http.StatusFound, "/login")
}

func generateJWT(userID string, isAdmin bool) string {
    claims := jwt.MapClaims{
        "user_id": userID,
        "is_admin": isAdmin,
        "exp": time.Now().Add(time.Hour * 24).Unix(),
        "iat": time.Now().Unix(),
    }
    
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    tokenString, err := token.SignedString([]byte(os.Getenv("JWT_SECRET")))
    if err != nil {
        return ""
    }
    return tokenString
}


func GetUserProfile(c *gin.Context) {
    userID := c.GetString("user_id")
    c.JSON(http.StatusOK, gin.H{"user_id": userID})
}

func UpdateUserProfile(c *gin.Context) {
    userID := c.GetString("user_id")
    c.JSON(http.StatusOK, gin.H{"message": "Profile updated", "user_id": userID})
}

func GetUserProjects(c *gin.Context) {
    userID := c.GetString("user_id")
    c.JSON(http.StatusOK, gin.H{"projects": []string{}, "user_id": userID})
}
