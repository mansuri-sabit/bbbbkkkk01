package models

import (
    "fmt"
    "time"
    "go.mongodb.org/mongo-driver/bson/primitive"
)

// User represents a user in the system
type User struct {
    ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Username  string             `bson:"username" json:"username"`
    Email     string             `bson:"email" json:"email"`
    Password  string             `bson:"password" json:"-"`
    IsActive  bool               `bson:"is_active" json:"is_active"`
    Role      string             `bson:"role" json:"role"`
    CreatedAt time.Time          `bson:"created_at" json:"created_at"`
    UpdatedAt time.Time          `bson:"updated_at" json:"updated_at"`
}

// ChatUser represents users who interact with embed chat widgets
type ChatUser struct {
    ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    ProjectID string             `bson:"project_id" json:"project_id"`
    Name      string             `bson:"name" json:"name"`
    Email     string             `bson:"email" json:"email"`
    Password  string             `bson:"password" json:"-"`
    CreatedAt time.Time          `bson:"created_at" json:"created_at"`
    IsActive  bool               `bson:"is_active" json:"is_active"`
}

// Project represents a chatbot project
type Project struct {
    ID              primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    Name            string             `bson:"name" json:"name"`
    Description     string             `bson:"description" json:"description"`
    Category        string             `bson:"category" json:"category"`
    IsActive        bool               `bson:"is_active" json:"is_active"`
    CreatedAt       time.Time          `bson:"created_at" json:"created_at"`
    UpdatedAt       time.Time          `bson:"updated_at" json:"updated_at"`
    
    // PDF Storage Fields
    PDFFiles        []PDFFile          `bson:"pdf_files" json:"pdf_files"`
    PDFContent      string             `bson:"pdf_content" json:"pdf_content"`
    
    // Simplified Gemini Configuration
    GeminiEnabled   bool               `bson:"gemini_enabled" json:"gemini_enabled"`
    GeminiAPIKey    string             `bson:"gemini_api_key" json:"gemini_api_key"`
    GeminiModel     string             `bson:"gemini_model" json:"gemini_model"`
    
    // Simplified Monthly Tracking (removed daily/cost fields)
    GeminiUsageMonth    int       `bson:"gemini_usage_month" json:"gemini_usage_month"`
    GeminiMonthlyLimit  int       `bson:"gemini_monthly_limit" json:"gemini_monthly_limit"`
    LastMonthlyReset    time.Time `bson:"last_monthly_reset" json:"last_monthly_reset"`
    
    // Keep essential analytics
    TotalQuestions  int                `bson:"total_questions" json:"total_questions"`
    LastUsed        time.Time          `bson:"last_used" json:"last_used"`
    WelcomeMessage  string             `bson:"welcome_message" json:"welcome_message"`
}

// PDFFile represents uploaded PDF files for each project
type PDFFile struct {
    ID          string    `bson:"id" json:"id"`
    FileName    string    `bson:"file_name" json:"file_name"`
    FilePath    string    `bson:"file_path" json:"file_path"`
    FileSize    int64     `bson:"file_size" json:"file_size"`
    UploadedAt  time.Time `bson:"uploaded_at" json:"uploaded_at"`
    ProcessedAt time.Time `bson:"processed_at" json:"processed_at"`
    Status      string    `bson:"status" json:"status"` // "processing", "completed", "failed"
}

// GeminiUsageLog tracks AI usage for analytics and billing
type GeminiUsageLog struct {
    ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    ProjectID   primitive.ObjectID `bson:"project_id" json:"project_id"`
    Question    string             `bson:"question" json:"question"`
    Response    string             `bson:"response" json:"response"`
    TokensUsed  int                `bson:"tokens_used" json:"tokens_used"`
    Timestamp   time.Time          `bson:"timestamp" json:"timestamp"`
    UserIP      string             `bson:"user_ip" json:"user_ip"`
    UserID      primitive.ObjectID `bson:"user_id,omitempty" json:"user_id,omitempty"`
    UserName    string             `bson:"user_name,omitempty" json:"user_name,omitempty"`
    Model           string             `bson:"model" json:"model"`
    InputTokens     int                `bson:"input_tokens" json:"input_tokens"`
    OutputTokens    int                `bson:"output_tokens" json:"output_tokens"`
    EstimatedCost   float64            `bson:"estimated_cost" json:"estimated_cost"`
    ResponseTime    int64              `bson:"response_time_ms" json:"response_time_ms"`
    Success         bool               `bson:"success" json:"success"`
}

// ChatMessage represents individual chat messages
type ChatMessage struct {
    ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    ProjectID primitive.ObjectID `bson:"project_id" json:"project_id"`
    SessionID string             `bson:"session_id" json:"session_id"`
    Message   string             `bson:"message" json:"message"`
    Response  string             `bson:"response" json:"response"`
    IsUser    bool               `bson:"is_user" json:"is_user"`
    Timestamp time.Time          `bson:"timestamp" json:"timestamp"`
    IPAddress string             `bson:"ip_address" json:"ip_address"`
    
    // User authentication fields
    UserID    primitive.ObjectID `bson:"user_id,omitempty" json:"user_id,omitempty"`
    UserName  string             `bson:"user_name,omitempty" json:"user_name,omitempty"`
    UserEmail string             `bson:"user_email,omitempty" json:"user_email,omitempty"`
    
    // Message rating and feedback
    Rating    int                `bson:"rating,omitempty" json:"rating,omitempty"`
    Feedback  string             `bson:"feedback,omitempty" json:"feedback,omitempty"`
    RatedAt   time.Time          `bson:"rated_at,omitempty" json:"rated_at,omitempty"`
}

// ChatSession represents a chat session
type ChatSession struct {
    ID        primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    ProjectID primitive.ObjectID `bson:"project_id" json:"project_id"`
    SessionID string             `bson:"session_id" json:"session_id"`
    UserID    primitive.ObjectID `bson:"user_id,omitempty" json:"user_id"`
    IsActive  bool               `bson:"is_active" json:"is_active"`
    StartTime time.Time          `bson:"start_time" json:"start_time"`
    EndTime   time.Time          `bson:"end_time" json:"end_time"`
    IPAddress string             `bson:"ip_address" json:"ip_address"`
}

type Notification struct {
    ID          primitive.ObjectID `bson:"_id,omitempty" json:"id"`
    ProjectID   primitive.ObjectID `bson:"project_id,omitempty" json:"project_id,omitempty"`
    UserID      primitive.ObjectID `bson:"user_id,omitempty" json:"user_id,omitempty"`
    Type        string             `bson:"type" json:"type"` // "limit_expired", "success", "warning", "error", "info"
    Title       string             `bson:"title" json:"title"`
    Message     string             `bson:"message" json:"message"`
    IsRead      bool               `bson:"is_read" json:"is_read"`
    CreatedAt   time.Time          `bson:"created_at" json:"created_at"`
    ExpiresAt   time.Time          `bson:"expires_at,omitempty" json:"expires_at,omitempty"`
    Metadata    map[string]interface{} `bson:"metadata,omitempty" json:"metadata,omitempty"`
}



// ===== HELPER METHODS =====

// IsAdmin checks if user has admin role
func (u *User) IsAdmin() bool {
    return u.Role == RoleAdmin
}

// IsUser checks if user has regular user role
func (u *User) IsUser() bool {
    return u.Role == RoleUser
}

// ✅ FIXED: Updated Validate method to use correct field names
func (p *Project) Validate() error {
    if p.Name == "" {
        return fmt.Errorf("project name is required")
    }
    if p.GeminiAPIKey == "" {
        return fmt.Errorf("gemini API key is required")
    }
    if p.GeminiMonthlyLimit <= 0 {  // ✅ FIXED: Use GeminiMonthlyLimit
        return fmt.Errorf("gemini monthly limit must be greater than 0")
    }
    return nil
}

// ✅ FIXED: Updated IsWithinLimit to use monthly fields
func (p *Project) IsWithinLimit() bool {
    return p.GeminiUsageMonth < p.GeminiMonthlyLimit
}

// ✅ FIXED: Updated GetUsagePercentage to use monthly fields
func (p *Project) GetUsagePercentage() float64 {
    if p.GeminiMonthlyLimit == 0 {
        return 0
    }
    return float64(p.GeminiUsageMonth) / float64(p.GeminiMonthlyLimit) * 100
}

// IsProcessed checks if PDF file is successfully processed
func (pdf *PDFFile) IsProcessed() bool {
    return pdf.Status == "completed"
}

// IsFailed checks if PDF processing failed
func (pdf *PDFFile) IsFailed() bool {
    return pdf.Status == "failed"
}

// ===== CONSTANTS =====

const (
    RoleUser  = "user"
    RoleAdmin = "admin"
)

// PDF Processing Status Constants
const (
    PDFStatusProcessing = "processing"
    PDFStatusCompleted  = "completed"
    PDFStatusFailed     = "failed"
)

// Gemini Model Constants
const (
    GeminiModelFlash = "gemini-1.5-flash"
    GeminiModelPro   = "gemini-1.5-pro"
)

const (
    NotificationTypeLimitExpired = "limit_expired"
    NotificationTypeSuccess      = "success"
    NotificationTypeWarning      = "warning"
    NotificationTypeError        = "error"
    NotificationTypeInfo         = "info"
)