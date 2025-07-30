package middleware

import (
    "net/http"
    "os"
    
    "github.com/gin-gonic/gin"
    "github.com/golang-jwt/jwt/v4"
)

func AdminAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        // Skip authentication for OPTIONS requests (CORS preflight)
        if c.Request.Method == "OPTIONS" {
            c.Next()
            return
        }
        
        token, err := c.Cookie("token")
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Authentication required",
                "message": "No valid token found",
            })
            c.Abort()
            return
        }
        
        claims := jwt.MapClaims{}
        parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
            return []byte(os.Getenv("JWT_SECRET")), nil
        })
        
        if err != nil || !parsedToken.Valid {
            c.JSON(http.StatusUnauthorized, gin.H{
                "error": "Invalid token",
                "message": "Token is expired or invalid",
            })
            c.Abort()
            return
        }
        
        isAdmin, ok := claims["is_admin"].(bool)
        if !ok || !isAdmin {
            c.JSON(http.StatusForbidden, gin.H{
                "error": "Access denied",
                "message": "Admin privileges required",
            })
            c.Abort()
            return
        }
        
        // Set user info in context
        c.Set("user_id", claims["user_id"])
        c.Set("is_admin", true)
        
        c.Next()
    }
}

func UserAuth() gin.HandlerFunc {
    return func(c *gin.Context) {
        if c.Request.Method == "OPTIONS" {
            c.Next()
            return
        }
        
        token, err := c.Cookie("token")
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
            c.Abort()
            return
        }
        
        claims := jwt.MapClaims{}
        parsedToken, err := jwt.ParseWithClaims(token, claims, func(token *jwt.Token) (interface{}, error) {
            return []byte(os.Getenv("JWT_SECRET")), nil
        })
        
        if err != nil || !parsedToken.Valid {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
            c.Abort()
            return
        }
        
        c.Set("user_id", claims["user_id"])
        c.Next()
    }
}
