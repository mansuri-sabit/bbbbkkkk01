package main

import (
    "log"
    "net/http"
    "os"
    "time"

    "github.com/gin-contrib/cors"
    "github.com/gin-gonic/gin"
    "github.com/joho/godotenv"
    "jevi-chat/config"
    "jevi-chat/handlers"
    "jevi-chat/middleware"
)

func main() {
    // Load .env variables
    if err := godotenv.Load(); err != nil {
        log.Println("⚠️ Warning: .env file not found, using system environment variables")
    }

    // Initialize services
    log.Println("🔗 Initializing MongoDB connection...")
    config.InitMongoDB()
    defer config.CloseMongoDB()

    // ✅ NEW: Initialize notification configuration
    log.Println("🔔 Initializing notification system...")
    config.InitNotificationConfig()

    // ✅ NEW: Start notification cleanup routine
    go startNotificationCleanup()

    // Initialize other services
    log.Println("🤖 Initializing Gemini...")
    config.InitGemini()
    
    log.Println("🚦 Initializing rate limiters...")
    handlers.InitRateLimiters()

    // Set up Gin
    if os.Getenv("GIN_MODE") == "release" {
        gin.SetMode(gin.ReleaseMode)
    }

    r := gin.New()
    
    // Add middleware
    r.Use(gin.Logger())
    r.Use(gin.Recovery())
    
    r.LoadHTMLGlob("templates/**/*.html")
    r.Static("/static", "./static")

    // Enhanced CORS setup
    corsConfig := cors.Config{
        AllowOrigins: []string{
            "https://troikafrontend.onrender.com",
            "http://localhost:3000",
            "http://127.0.0.1:3000",
            "http://localhost:3001",
            "http://127.0.0.1:3001",
            "http://localhost:8081",
            "http://localhost:8080", // your local frontend/backend
            "http://127.0.0.1:8080",
        },
        AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH", "HEAD"},
        AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "Authorization", "X-Requested-With", "X-CSRF-Token", "Cache-Control"},
        ExposeHeaders:    []string{"Content-Length", "Content-Type", "X-RateLimit-Remaining", "X-RateLimit-Reset", "Retry-After"},
        AllowCredentials: true,
        MaxAge:           12 * time.Hour,
    }

    // Add custom CORS allowed origins from environment
    if customOrigins := os.Getenv("CORS_ALLOWED_ORIGINS"); customOrigins != "" {
        corsConfig.AllowOrigins = append(corsConfig.AllowOrigins, customOrigins)
    }

    r.Use(cors.New(corsConfig))

    // Dev-only: Allow null origin
    if gin.Mode() == gin.DebugMode {
        corsConfig.AllowOrigins = append(corsConfig.AllowOrigins, "null")
        log.Println("🔍 CORS: Allowing 'null' origin for development")
    }

    // Enhanced security headers
    r.Use(func(c *gin.Context) {
        c.Header("X-Frame-Options", "ALLOWALL")
        c.Header("Content-Security-Policy", "frame-ancestors *")
        c.Header("X-Content-Type-Options", "nosniff")
        c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
        c.Header("X-XSS-Protection", "1; mode=block")
        c.Next()
    })

    // Setup routes
    setupRoutes(r)

    // Widget assets
    r.GET("/widget.js", func(c *gin.Context) {
        c.File("./static/js/jevi-chat-widget.js")
    })
    r.GET("/widget.css", func(c *gin.Context) {
        c.File("./static/css/jevi-widget.css")
    })

    // ✅ NEW: Start maintenance tasks
    go startMaintenanceTasks()

    // Start server
    port := os.Getenv("PORT")
    if port == "" || len(port) > 5 {
        port = "8080"
    }

    log.Printf("🚀 Jevi Chat Server running on port %s", port)
    log.Printf("📝 Environment: %s", gin.Mode())
    log.Printf("🔔 Notification system: %s", getNotificationStatus())
    log.Printf("🤖 Gemini model: gemini-2.0-flash")
    
    if err := http.ListenAndServe("0.0.0.0:"+port, r); err != nil {
        log.Fatalf("❌ Failed to start server: %v", err)
    }
}

func setupRoutes(r *gin.Engine) {
    // Enhanced health check
    r.GET("/health", func(c *gin.Context) {
        if err := config.HealthCheck(); err != nil {
            c.JSON(http.StatusServiceUnavailable, gin.H{
                "status": "unhealthy",
                "error":  err.Error(),
            })
            return
        }

        c.JSON(http.StatusOK, gin.H{
            "status":       "healthy",
            "service":      "jevi-chat",
            "version":      "1.0.0",
            "cors":         "enabled",
            "iframe":       "enabled",
            "rateLimit":    "enabled",
            "notifications": getNotificationStatus(),
            "gemini_model": "gemini-2.0-flash",
            "timestamp":    time.Now().Format(time.RFC3339),
        })
    })

    r.GET("/cors-test", handlers.RateLimitMiddleware("general"), func(c *gin.Context) {
        c.JSON(http.StatusOK, gin.H{
            "message": "CORS is working!",
            "origin":  c.Request.Header.Get("Origin"),
            "method":  c.Request.Method,
            "iframe":  "supported",
        })
    })

    // Embed routes
    embed := r.Group("/embed/:projectId")
    embed.Use(handlers.RateLimitMiddleware("general"))
    {
        embed.GET("", handlers.EmbedChat)
        embed.GET("/chat", handlers.IframeChatInterface)

        auth := embed.Group("/auth")
        auth.Use(handlers.RateLimitMiddleware("auth"))
        {
            auth.GET("", handlers.EmbedAuth)
            auth.POST("", handlers.EmbedAuth)
        }

        embed.POST("/message", handlers.RateLimitMiddleware("chat"), handlers.IframeSendMessage)
    }

    r.GET("/embed/health", handlers.EmbedHealth)

    // Public Auth Routes
    authRoutes := r.Group("/")
    authRoutes.Use(handlers.RateLimitMiddleware("auth"))
    {
        authRoutes.POST("/login", handlers.Login)
        authRoutes.GET("/logout", handlers.Logout)
        authRoutes.GET("/register", handlers.RegisterPage)
        authRoutes.POST("/register", handlers.Register)
    }

    // ===== API ROUTES =====
    api := r.Group("/api")
    api.Use(handlers.RateLimitMiddleware("general"))
    {
        // Public auth endpoints
        api.POST("/login", handlers.Login)
        api.POST("/register", handlers.Register)
        api.POST("/logout", handlers.Logout)

        // ✅ NEW: Public notification health check
        api.GET("/notifications/health", func(c *gin.Context) {
            c.JSON(http.StatusOK, gin.H{
                "status": "healthy",
                "service": "notifications",
                "timestamp": time.Now().Format(time.RFC3339),
            })
        })

        // ✅ NEW: Test notification system (development only)
        if gin.Mode() == gin.DebugMode {
            api.GET("/notifications/test", handlers.TestNotificationSystem)
        }

        // Protected API routes
        protected := api.Group("/")
        protected.Use(middleware.AdminAuth())
        {
            // ✅ NEW: Notification routes
            protected.GET("/notifications", handlers.GetNotifications)
            protected.PUT("/notifications/:id/read", handlers.MarkNotificationAsRead)
            protected.PUT("/notifications/read-all", handlers.MarkAllNotificationsAsRead)
            protected.DELETE("/notifications/:id", handlers.DeleteNotification)

            // User routes
            protected.GET("/user/profile", handlers.GetUserProfile)
            protected.PUT("/user/profile", handlers.UpdateUserProfile)
            protected.GET("/user/projects", handlers.GetUserProjects)

            // Project routes
            protected.GET("/projects/:id", handlers.ProjectDetails)
            protected.GET("/projects/:id/info", handlers.GetProjectInfo)
            protected.GET("/projects/:id/chat/history", handlers.GetChatHistory)
            protected.GET("/projects/:id/chat/analytics", handlers.GetChatAnalytics)
            protected.POST("/projects/:id/chat/send", handlers.SendMessage)
            protected.PUT("/projects/:id/chat/messages/:messageId/rate", handlers.RateMessage)
            protected.GET("/projects/:id/notifications", handlers.GetProjectNotifications)

            // PDF management
            protected.POST("/projects/:id/pdf/upload", handlers.UploadPDF)
            protected.DELETE("/projects/:id/pdf/:fileId", handlers.DeletePDF)
            protected.GET("/projects/:id/pdf/files", handlers.GetPDFFiles)
        }

        // Legacy admin routes (keeping for backward compatibility)
        api.GET("/admin/dashboard", handlers.AdminDashboard)
        api.GET("/admin/projects", handlers.AdminProjects)
        api.POST("/admin/projects", handlers.CreateProject)
        api.GET("/admin/users", handlers.AdminUsers)
        api.DELETE("/admin/users/:id", handlers.DeleteUser)
        api.GET("/project/:id", handlers.ProjectDetails)
        api.PUT("/project/:id", handlers.UpdateProject)
        api.DELETE("/project/:id", handlers.DeleteProject)
        api.GET("/admin/notifications", handlers.GetNotifications)
        api.GET("/admin/realtime-stats", handlers.GetRealtimeStats)
    }

    // ===== ADMIN ROUTES =====
    admin := r.Group("/admin")
    admin.Use(handlers.RateLimitMiddleware("general"))
    admin.Use(func(c *gin.Context) {
        if c.Request.Method == "OPTIONS" {
            c.Next()
            return
        }
        middleware.AdminAuth()(c)
    })
    {
        // Dashboard
        admin.GET("/", handlers.AdminDashboard)
        admin.GET("/dashboard", handlers.AdminDashboard)

        // Projects management
        admin.GET("/projects", handlers.AdminProjects)
        admin.POST("/projects", handlers.CreateProject)
        admin.GET("/projects/:id", handlers.ProjectDetails)
        admin.PUT("/projects/:id", handlers.UpdateProject)
        admin.DELETE("/projects/:id", handlers.DeleteProject)
        admin.PATCH("/projects/:id/toggle", handlers.ToggleProjectStatus)

        // ✅ NEW: Enhanced Gemini management with notifications
        admin.PATCH("/projects/:id/gemini/toggle", handlers.ToggleGeminiStatus)
        admin.PATCH("/projects/:id/gemini/limit", handlers.SetGeminiLimit)
        admin.POST("/projects/:id/gemini/reset", handlers.ResetGeminiUsage)
        admin.GET("/projects/:id/gemini/analytics", handlers.GetGeminiAnalytics)

        // ✅ NEW: Monthly limit management (simplified schema)
        admin.PUT("/projects/:id/gemini/monthly-limit", handlers.SetMonthlyGeminiLimit)
        admin.POST("/projects/:id/gemini/reset-monthly", handlers.ResetMonthlyUsage)
        admin.GET("/projects/limits", handlers.GetProjectsWithLimits)

        // Users management
        admin.GET("/users", handlers.AdminUsers)
        admin.GET("/users/:id", handlers.GetUserDetails)
        admin.PUT("/users/:id", handlers.UpdateUser)
        admin.DELETE("/users/:id", handlers.DeleteUser)
        admin.PUT("/users/:id/toggle", handlers.ToggleUserStatus)

        // ✅ NEW: Enhanced notification management
        admin.GET("/notifications", handlers.GetNotifications)
        admin.GET("/notifications/stats", handlers.GetNotificationStats)
        admin.DELETE("/notifications/:id", handlers.DeleteNotification)
        admin.PUT("/notifications/cleanup", func(c *gin.Context) {
            if err := handlers.CleanupExpiredNotifications(); err != nil {
                c.JSON(http.StatusInternalServerError, gin.H{
                    "success": false,
                    "error": "Failed to cleanup notifications",
                })
                return
            }
            c.JSON(http.StatusOK, gin.H{
                "success": true,
                "message": "Notification cleanup completed",
            })
        })

        // Analytics and settings
        admin.GET("/analytics", handlers.AdminAnalytics)
        admin.GET("/analytics/data", handlers.GetAnalyticsData)
        admin.GET("/settings", handlers.AdminSettings)
        admin.PUT("/settings", handlers.UpdateSettings)
        admin.GET("/realtime-stats", handlers.GetRealtimeStats)

       

        // ✅ NEW: Database management
        admin.GET("/database/stats", func(c *gin.Context) {
            stats := config.GetDetailedDatabaseStats()
            c.JSON(http.StatusOK, gin.H{
                "success": true,
                "stats": stats,
            })
        })
    }

    // ===== USER ROUTES =====
    user := r.Group("/user")
    user.Use(handlers.RateLimitMiddleware("general"))
    user.Use(func(c *gin.Context) {
        if c.Request.Method == "OPTIONS" {
            c.Next()
            return
        }
        middleware.UserAuth()(c)
    })
    {
        user.GET("/dashboard", handlers.UserDashboard)
        user.GET("/project/:id", handlers.ProjectDashboard)
        user.GET("/chat/:id", handlers.IframeChatInterface)
        user.POST("/chat/:id/message", handlers.RateLimitMiddleware("chat"), handlers.SendMessage)
        user.POST("/project/:id/upload", handlers.UploadPDF)
        user.GET("/notifications", handlers.GetNotifications)
        user.GET("/projects", handlers.UserProjects)
    }

    // ✅ Public Chat History Route (without auth)
    r.GET("/user/chat/:id/history", handlers.RateLimitMiddleware("general"), handlers.GetChatHistory)
     // PDF management
      r.POST("/projects/:id/upload-pdf", handlers.UploadPDF)
        admin.DELETE("/projects/:id/pdf/:fileId", handlers.DeletePDF)
        admin.GET("/projects/:id/pdf/files", handlers.GetPDFFiles)
    // ===== CHAT ROUTES =====
    chat := r.Group("/chat")
    chat.Use(handlers.RateLimitMiddleware("chat"))
    {
        chat.POST("/:projectId/message", handlers.IframeSendMessage)
        chat.GET("/:projectId/history", handlers.GetChatHistory)
        chat.POST("/:projectId/rate/:messageId", handlers.RateMessage)
    }

    // ===== PROJECT DASHBOARD ROUTES =====
    project := r.Group("/project")
    project.Use(middleware.AdminAuth())
    {
        project.GET("/:id/dashboard", handlers.ProjectDashboard)
    }

    // 404 / method not allowed
    r.NoRoute(func(c *gin.Context) {
        c.JSON(http.StatusNotFound, gin.H{
            "error":   "Route not found",
            "message": "The requested endpoint does not exist",
            "path":    c.Request.URL.Path,
            "method":  c.Request.Method,
        })
    })

    r.NoMethod(func(c *gin.Context) {
        c.JSON(http.StatusMethodNotAllowed, gin.H{
            "error":   "Method not allowed",
            "message": "This HTTP method is not allowed for this endpoint",
            "path":    c.Request.URL.Path,
            "method":  c.Request.Method,
        })
    })
}

// ✅ NEW: Background notification cleanup routine
func startNotificationCleanup() {
    interval := 24 * time.Hour
    if config.NotificationSettings != nil && config.NotificationSettings.EnableCleanup {
        interval = config.NotificationSettings.CleanupInterval
    } else if config.NotificationSettings != nil && !config.NotificationSettings.EnableCleanup {
        log.Println("🔔 Notification cleanup is disabled")
        return
    }

    log.Printf("🔔 Starting notification cleanup routine (interval: %v)", interval)
    
    ticker := time.NewTicker(interval)
    defer ticker.Stop()

    // Run cleanup immediately on startup
    if err := handlers.CleanupExpiredNotifications(); err != nil {
        log.Printf("⚠️ Initial notification cleanup failed: %v", err)
    }

    for {
        select {
        case <-ticker.C:
            if err := handlers.CleanupExpiredNotifications(); err != nil {
                log.Printf("⚠️ Notification cleanup failed: %v", err)
            } else {
                log.Println("✅ Notification cleanup completed successfully")
            }
        }
    }
}

// ✅ NEW: General maintenance tasks
func startMaintenanceTasks() {
    // Run maintenance every 6 hours
    ticker := time.NewTicker(6 * time.Hour)
    defer ticker.Stop()

    log.Println("🔧 Starting maintenance tasks routine...")

    for {
        select {
        case <-ticker.C:
            log.Println("🔧 Running periodic maintenance...")
            
            // Perform database maintenance
            if err := config.PerformMaintenance(); err != nil {
                log.Printf("⚠️ Maintenance failed: %v", err)
            } else {
                log.Println("✅ Maintenance completed successfully")
            }
        }
    }
}

// ✅ NEW: Helper function to get notification status
func getNotificationStatus() string {
    if config.NotificationSettings == nil {
        return "not configured"
    }
    
    if config.NotificationSettings.EnableCleanup {
        return "enabled with cleanup"
    }
    
    return "enabled"
}
