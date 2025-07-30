package handlers

import (
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/generative-ai-go/genai"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo/options"
	"google.golang.org/api/option"
	"html"
	"jevi-chat/config"
	"jevi-chat/models"
	"log"
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ===== RATE LIMITING IMPLEMENTATION =====

type RateLimiter struct {
	visitors map[string]*Visitor
	mu       sync.RWMutex
	rate     time.Duration
	burst    int
}

type Visitor struct {
	lastSeen time.Time
	count    int
	window   time.Time
}

var (
	// Rate limiters for different endpoints
	chatRateLimiter    *RateLimiter
	authRateLimiter    *RateLimiter
	generalRateLimiter *RateLimiter
)

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(rate time.Duration, burst int) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*Visitor),
		rate:     rate,
		burst:    burst,
	}

	// Clean up old visitors every 5 minutes
	go rl.cleanupVisitors()

	return rl
}

// Allow checks if the request is allowed
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	visitor, exists := rl.visitors[ip]
	if !exists {
		visitor = &Visitor{
			lastSeen: now,
			count:    1,
			window:   now.Truncate(rl.rate),
		}
		rl.visitors[ip] = visitor
		return true
	}

	// Check if we're in a new time window
	currentWindow := now.Truncate(rl.rate)
	if visitor.window.Before(currentWindow) {
		visitor.count = 1
		visitor.window = currentWindow
		visitor.lastSeen = now
		return true
	}

	// Check if under burst limit
	if visitor.count < rl.burst {
		visitor.count++
		visitor.lastSeen = now
		return true
	}

	return false
}

// GetRemainingRequests returns remaining requests in current window
func (rl *RateLimiter) GetRemainingRequests(ip string) int {
	rl.mu.RLock()
	defer rl.mu.RUnlock()

	visitor, exists := rl.visitors[ip]
	if !exists {
		return rl.burst
	}

	now := time.Now()
	currentWindow := now.Truncate(rl.rate)

	if visitor.window.Before(currentWindow) {
		return rl.burst
	}

	remaining := rl.burst - visitor.count
	if remaining < 0 {
		return 0
	}
	return remaining
}

// cleanupVisitors removes old visitors
func (rl *RateLimiter) cleanupVisitors() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			rl.mu.Lock()
			cutoff := time.Now().Add(-10 * time.Minute)
			for ip, visitor := range rl.visitors {
				if visitor.lastSeen.Before(cutoff) {
					delete(rl.visitors, ip)
				}
			}
			rl.mu.Unlock()
		}
	}
}

// InitRateLimiters initializes rate limiters
func InitRateLimiters() {
	// Chat endpoints: 30 requests per minute
	chatRateLimiter = NewRateLimiter(time.Minute, 30)

	// Auth endpoints: 10 requests per minute (more restrictive)
	authRateLimiter = NewRateLimiter(time.Minute, 10)

	// General endpoints: 60 requests per minute
	generalRateLimiter = NewRateLimiter(time.Minute, 60)
}

// ===== MAIN CHAT HANDLERS =====

// SendMessage - For authenticated users in the main dashboard
func SendMessage(c *gin.Context) {
	projectID := c.Param("id")
	clientIP := c.ClientIP()

	var messageData struct {
		Message   string `json:"message"`
		SessionID string `json:"session_id"`
	}

	if err := c.ShouldBindJSON(&messageData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message data"})
		return
	}

	// Sanitize input
	messageData.Message = sanitizeInput(messageData.Message)
	if messageData.Message == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Message cannot be empty"})
		return
	}

	// Enhanced rate limiting with proper response
	if !checkRateLimit(clientIP) {
		remaining := 0
		if chatRateLimiter != nil {
			remaining = chatRateLimiter.GetRemainingRequests(clientIP)
		}

		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))
		c.Header("Retry-After", "60")

		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":       "Rate limit exceeded",
			"message":     "Too many requests. Please wait before sending another message.",
			"retry_after": 60,
			"remaining":   remaining,
		})
		return
	}

	// Get project with PDF content
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

	// Check if project is active
	if !project.IsActive {
		c.JSON(http.StatusForbidden, gin.H{"error": "Project is inactive"})
		return
	}

	var response string
	var err2 error

	// Check if Gemini is enabled and within limits
	if project.GeminiEnabled && project.GeminiUsageMonth < project.GeminiMonthlyLimit && project.GeminiAPIKey != "" {
		// First-message greeting logic + 4-second human-like delay
		if isFirstMessage(objID, messageData.SessionID) {
			time.Sleep(4 * time.Second)
			response = project.WelcomeMessage
		} else {
			time.Sleep(4 * time.Second) // keep the same pause for regular replies
			response, err2 = generateAIResponse(
				messageData.Message,
				project.PDFContent,
				project.GeminiAPIKey,
				project.Name,
				project.GeminiModel,
			)
			if err2 != nil {
				// Fallback response
				response = fmt.Sprintf("I apologize, but I'm experiencing technical difficulties with my AI system. However, I received your message about %s and will help you as best I can. Please try rephrasing your question.", project.Name)
			} else {
				// Update monthly usage counter asynchronously (corrected function name)
				go updateMonthlyGeminiUsage(objID)
			}
		}
	} else {
		// Gemini disabled, limit reached, or no API key
		time.Sleep(4 * time.Second) // consistent delay even for error messages
		if !project.GeminiEnabled {
			response = "AI responses are currently disabled for this project."
		} else if project.GeminiAPIKey == "" {
			response = "AI configuration is incomplete. Please contact the administrator."
		} else {
			// ✅ NEW: Proper limit exceeded message
			response = "Your limit has expired."
		}
	}

	// Save chat message to database
	chatMessage := models.ChatMessage{
		ProjectID: objID,
		SessionID: messageData.SessionID,
		Message:   messageData.Message,
		Response:  response,
		IsUser:    false,
		Timestamp: time.Now(),
		IPAddress: clientIP,
	}

	chatCollection := config.DB.Collection("chat_messages")
	result, err := chatCollection.InsertOne(context.Background(), chatMessage)
	if err != nil {
		// Log error but still return response
		fmt.Printf("Failed to save chat message: %v\n", err)
	} else {
		chatMessage.ID = result.InsertedID.(primitive.ObjectID)
	}

	// Add rate limit headers to response
	if chatRateLimiter != nil {
		remaining := chatRateLimiter.GetRemainingRequests(clientIP)
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))
	}

	c.JSON(http.StatusOK, gin.H{
		"response":   response,
		"message_id": chatMessage.ID,
		"timestamp":  chatMessage.Timestamp,
		"session_id": messageData.SessionID,
		"usage_info": gin.H{},
	})
}

// IframeSendMessage - For embed widget users with enhanced features
func IframeSendMessage(c *gin.Context) {
	projectID := c.Param("projectId")

	clientIP := c.ClientIP()

	objID, err := primitive.ObjectIDFromHex(projectID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
		return
	}

	var messageData struct {
		Message   string `json:"message"`
		SessionID string `json:"session_id"`
		UserToken string `json:"user_token"`
	}

	if err := c.ShouldBindJSON(&messageData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message data"})
		return
	}

	// Enhanced rate limiting with proper response
	if !checkRateLimit(clientIP) {
		remaining := 0
		if chatRateLimiter != nil {
			remaining = chatRateLimiter.GetRemainingRequests(clientIP)
		}

		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))
		c.Header("Retry-After", "60")
		c.JSON(http.StatusTooManyRequests, gin.H{
			"error":       "Rate limit exceeded",
			"message":     "Too many requests. Please wait before sending another message.",
			"retry_after": 60,
			"remaining":   remaining,
		})
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

	// Check if project is active
	if !project.IsActive {
		c.JSON(http.StatusForbidden, gin.H{"error": "This chat is currently unavailable"})
		return
	}

	// Check if Gemini is enabled
	if !project.GeminiEnabled {
		c.JSON(http.StatusForbidden, gin.H{
			"error":  "AI responses are currently disabled for this project",
			"status": "gemini_disabled",
		})
		return
	}

	// ✅ MAIN CHANGE: Check monthly usage limits with "Your limit has expired" message
if project.GeminiUsageMonth >= project.GeminiMonthlyLimit {
    time.Sleep(4 * time.Second) // Consistent delay
    
    // ✅ NEW: Create limit expired notification
    go CreateLimitExpiredNotification(
        objID,
        project.Name,
        "monthly",
        project.GeminiUsageMonth,
        project.GeminiMonthlyLimit,
    )
    
    c.JSON(http.StatusOK, gin.H{
        "response": "Your limit has expired.",
        "status": "monthly_limit_exceeded",
        "project_id": projectID,
        "timestamp": time.Now().Format(time.RFC3339),
        "usage_info": gin.H{
            "monthly_usage": project.GeminiUsageMonth,
            "monthly_limit": project.GeminiMonthlyLimit,
            "resets_at": getNextMonthlyReset(),
        },
    })
    return
}

	// Generate AI response and update monthly counter
	var response string
	time.Sleep(4 * time.Second) // Consistent delay

	if isFirstMessage(objID, messageData.SessionID) {
		response = project.WelcomeMessage
	} else if project.GeminiAPIKey != "" {
		response, err = generateAIResponse(
			messageData.Message,
			project.PDFContent,
			project.GeminiAPIKey,
			project.Name,
			project.GeminiModel,
		)
		if err != nil {
			response = "I'm having trouble answering just now. Please try again later."
		} else {
			// Update monthly usage counter
			go updateMonthlyGeminiUsage(objID)
		}
	} else {
		response = "AI configuration is incomplete. Please contact support."
	}

	// Save message to database
	saveMessage(objID, messageData.Message, response, messageData.SessionID, clientIP, models.ChatUser{})

	c.JSON(http.StatusOK, gin.H{
		"response":   response,
		"project_id": projectID,
		"status":     "success",
		"timestamp":  time.Now().Format(time.RFC3339),
		"usage_info": gin.H{
			"monthly_usage":     project.GeminiUsageMonth + 1,
			"monthly_limit":     project.GeminiMonthlyLimit,
			"monthly_remaining": project.GeminiMonthlyLimit - project.GeminiUsageMonth - 1,
		},
	})
}

// updateMonthlyGeminiUsage - Simplified usage update function
func updateMonthlyGeminiUsage(projectID primitive.ObjectID) {
	collection := config.DB.Collection("projects")
	_, err := collection.UpdateOne(
		context.Background(),
		bson.M{"_id": projectID},
		bson.M{
			"$inc": bson.M{
				"gemini_usage_month": 1, // ✅ FIXED: Use correct field name
				"total_questions":    1,
			},
			"$set": bson.M{
				"last_used":  time.Now(),
				"updated_at": time.Now(),
			},
		},
	)
	if err != nil {
		fmt.Printf("Failed to update monthly Gemini usage: %v\n", err)
	}
}

func generateAIResponse(userMessage, pdfContent, geminiKey, projectName, geminiModel string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := genai.NewClient(ctx, option.WithAPIKey(geminiKey))
	if err != nil {
		return "", fmt.Errorf("failed to create Gemini client: %v", err)
	}
	defer client.Close()

	// ✅ UPDATED: Use gemini-2.0-flash as default
	if geminiModel == "" {
		geminiModel = "gemini-2.0-flash"
	}

	model := client.GenerativeModel(geminiModel)
	model.SetTemperature(0.85)
	model.SetTopP(0.9)
	model.SetTopK(40)

	// Enhanced prompt with assistant identity and tone control
	prompt := fmt.Sprintf(`
You are the official support assistant for "%s". Always speak confidently and professionally **as if you are a real human assistant working at this company**.

DOCUMENT CONTEXT:
%s

USER QUESTION:
%s

RESPONSE RULES:
– Respond as the company representative (do not mention AI or language model)
– Base your reply on the document if possible. Otherwise, give a helpful fallback
– Keep a warm, helpful, and human-like tone (avoid robotic/formal phrases)
– Keep answers short: 2-3 complete and varied sentences unless explanation is needed
– Do not repeat phrases or words unnecessarily
– Never say "based on the document" or "I am an AI assistant"
– Reply like a human would, with confidence, care, and clear communication

Answer:`, projectName, pdfContent, userMessage)

	resp, err := model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return "", fmt.Errorf("failed to generate content: %v", err)
	}

	if len(resp.Candidates) > 0 && len(resp.Candidates[0].Content.Parts) > 0 {
		return fmt.Sprintf("%v", resp.Candidates[0].Content.Parts[0]), nil
	}

	return "I'm sorry, I couldn't generate a response at the moment. Please try again.", nil
}

// generateGeminiResponse - Enhanced response generation for embed users
func generateGeminiResponse(project models.Project, userMessage, userIP string, user models.ChatUser) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := genai.NewClient(ctx, option.WithAPIKey(project.GeminiAPIKey))
	if err != nil {
		return "", err
	}
	defer client.Close()

	// Use specified model or default
	modelName := project.GeminiModel
	if modelName == "" {
		modelName = "gemini-1.5-flash"
	}

	model := client.GenerativeModel(modelName)

	// Configure model for better responses
	model.SetTemperature(0.85)
	model.SetTopP(0.9)
	model.SetTopK(40)

	// Personalized greeting if user is known
	userContext := ""
	if user.Name != "" {
		userContext = fmt.Sprintf("The user's name is %s. ", user.Name)
	}

	// Enhanced prompt with natural tone
	// Refined, assistant-like prompt
	prompt := fmt.Sprintf(`You are the official customer support assistant for "%s". %s
Always respond as if you are a real, human assistant working at the company.
Never mention you're an AI or language model.

COMPANY KNOWLEDGE:
%s

USER QUESTION:
%s

RESPONSE RULES:
- Speak like a human company support executive
- Avoid robotic phrases, disclaimers, or repetitions
- Give clear answers based on the company knowledge above
- If an answer isn't found, respond politely and offer help
- Use warm, natural tone and avoid saying "based on the document"
- Keep it concise: 2–3 sentences max, unless more is needed
- Always end smoothly — never with generic filler like "I hope this helps"

Your reply:`, project.Name, userContext, project.PDFContent, userMessage)

	resp, err := model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return "", err
	}

	if len(resp.Candidates) > 0 && len(resp.Candidates[0].Content.Parts) > 0 {
		response := fmt.Sprintf("%v", resp.Candidates[0].Content.Parts[0])

		// Log usage asynchronously
		go logGeminiUsage(project.ID, userMessage, response, userIP, user)

		return response, nil
	}

	return "", fmt.Errorf("no response generated")
}

// generateGeminiResponseWithTracking - Enhanced AI response generation with token tracking
func generateGeminiResponseWithTracking(project models.Project, userMessage, userIP string, user models.ChatUser) (string, int, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	client, err := genai.NewClient(ctx, option.WithAPIKey(project.GeminiAPIKey))
	if err != nil {
		return "", 0, 0, fmt.Errorf("failed to create Gemini client: %v", err)
	}
	defer client.Close()

	// Use specified model or default
	modelName := project.GeminiModel
	if modelName == "" {
		modelName = "gemini-1.5-flash"
	}

	model := client.GenerativeModel(modelName)

	// Configure model for better responses
	model.SetTemperature(0.85)
	model.SetTopP(0.9)
	model.SetTopK(40)

	// Personalized greeting if user is known
	userContext := ""
	if user.Name != "" {
		userContext = fmt.Sprintf("The user's name is %s. ", user.Name)
	}

	// Enhanced prompt with anti-repetition and natural tone instructions
	prompt := fmt.Sprintf(`
You are a helpful AI assistant for %s. %sRespond naturally and conversationally without repeating phrases.

KNOWLEDGE BASE:
%s

USER QUESTION:
%s

GUIDELINES:
– Base the answer on the knowledge-base content when possible  
– Use a warm, friendly tone (avoid robotic phrases)  
– Keep it short: 2-3 well-formed sentences unless detail is essential  
– **Never** repeat any word, phrase, or sentence in the same reply  
– Vary your wording and sentence structure  
– If the docs don't contain the answer, say so politely and offer general help  
– End the reply naturally without filler or repetition.

Answer:`, project.Name, userContext, project.PDFContent, userMessage)

	resp, err := model.GenerateContent(ctx, genai.Text(prompt))
	if err != nil {
		return "", 0, 0, fmt.Errorf("failed to generate content: %v", err)
	}

	if len(resp.Candidates) > 0 && len(resp.Candidates[0].Content.Parts) > 0 {
		response := fmt.Sprintf("%v", resp.Candidates[0].Content.Parts[0])

		// Estimate token usage (approximate values since Gemini API doesn't return exact counts)
		inputTokens := estimateTokens(prompt)
		outputTokens := estimateTokens(response)

		return response, inputTokens, outputTokens, nil
	}

	return "", 0, 0, fmt.Errorf("no response generated")
}

// ===== CHAT HISTORY AND ANALYTICS =====

// GetChatHistory - Retrieve chat history with enhanced filtering
func GetChatHistory(c *gin.Context) {
	projectID := c.Param("id")
	sessionID := c.Query("session_id")
	limit := c.DefaultQuery("limit", "50")
	page := c.DefaultQuery("page", "1")

	objID, err := primitive.ObjectIDFromHex(projectID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
		return
	}

	filter := bson.M{"project_id": objID}
	if sessionID != "" {
		filter["session_id"] = sessionID
	}

	// Pagination options
	opts := options.Find().
		SetSort(bson.D{{"timestamp", -1}}).
		SetLimit(50) // Max 50 messages per request

	collection := config.DB.Collection("chat_messages")
	cursor, err := collection.Find(context.Background(), filter, opts)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch chat history"})
		return
	}
	defer cursor.Close(context.Background())

	var messages []models.ChatMessage
	if err := cursor.All(context.Background(), &messages); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse chat history"})
		return
	}

	// Get total count
	totalCount, _ := collection.CountDocuments(context.Background(), filter)

	c.JSON(http.StatusOK, gin.H{
		"messages":    messages,
		"count":       len(messages),
		"total_count": totalCount,
		"page":        page,
		"limit":       limit,
	})
}

// GetChatAnalytics - Get chat analytics for a project
func GetChatAnalytics(c *gin.Context) {
	projectID := c.Param("id")
	objID, err := primitive.ObjectIDFromHex(projectID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
		return
	}

	collection := config.DB.Collection("chat_messages")

	// Get total messages count
	totalMessages, _ := collection.CountDocuments(context.Background(), bson.M{"project_id": objID})

	// Get messages from last 7 days
	weekAgo := time.Now().AddDate(0, 0, -7)
	recentMessages, _ := collection.CountDocuments(context.Background(), bson.M{
		"project_id": objID,
		"timestamp":  bson.M{"$gte": weekAgo},
	})

	// Get unique sessions
	pipeline := []bson.M{
		{"$match": bson.M{"project_id": objID}},
		{"$group": bson.M{"_id": "$session_id"}},
		{"$count": "unique_sessions"},
	}

	cursor, _ := collection.Aggregate(context.Background(), pipeline)
	var result []bson.M
	cursor.All(context.Background(), &result)

	uniqueSessions := int64(0)
	if len(result) > 0 {
		if count, ok := result[0]["unique_sessions"].(int32); ok {
			uniqueSessions = int64(count)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_messages":  totalMessages,
		"recent_messages": recentMessages,
		"unique_sessions": uniqueSessions,
		"period":          "last_7_days",
	})
}

// ===== UTILITY FUNCTIONS =====

// isFirstMessage returns true the very first time a given session_id
// is seen for the project. It works by counting existing chat_messages.
func isFirstMessage(projectID primitive.ObjectID, sessionID string) bool {
	count, _ := config.DB.Collection("chat_messages").
		CountDocuments(context.Background(), bson.M{
			"project_id": projectID,
			"session_id": sessionID,
		})
	return count == 0
}

// saveMessage - Save chat message with user context
func saveMessage(projectID primitive.ObjectID, message, response, sessionID, userIP string, user models.ChatUser) {
	chatMessage := models.ChatMessage{
		ProjectID: projectID,
		SessionID: sessionID,
		Message:   message,
		Response:  response,
		IsUser:    false,
		Timestamp: time.Now(),
		IPAddress: userIP,
	}

	// Add user info if available
	if user.ID != primitive.NilObjectID {
		chatMessage.UserID = user.ID
		chatMessage.UserName = user.Name
		chatMessage.UserEmail = user.Email
	}

	chatCollection := config.DB.Collection("chat_messages")
	_, err := chatCollection.InsertOne(context.Background(), chatMessage)
	if err != nil {
		fmt.Printf("Failed to save chat message: %v\n", err)
	}
}

// updateGeminiUsage - Update usage counters
func updateGeminiUsage(projectID primitive.ObjectID) {
	collection := config.DB.Collection("projects")
	_, err := collection.UpdateOne(
		context.Background(),
		bson.M{"_id": projectID},
		bson.M{
			"$inc": bson.M{"gemini_usage": 1, "total_questions": 1},
			"$set": bson.M{"last_used": time.Now()},
		},
	)
	if err != nil {
		fmt.Printf("Failed to update Gemini usage: %v\n", err)
	}
}

// logGeminiUsage - Log detailed usage information
func logGeminiUsage(projectID primitive.ObjectID, question, response, userIP string, user models.ChatUser) {
	log := models.GeminiUsageLog{
		ProjectID: projectID,
		Question:  question,
		Response:  response,
		Timestamp: time.Now(),
		UserIP:    userIP,
	}

	// Add user info if available
	if user.ID != primitive.NilObjectID {
		log.UserID = user.ID
		log.UserName = user.Name
	}

	collection := config.DB.Collection("gemini_usage_logs")
	_, err := collection.InsertOne(context.Background(), log)
	if err != nil {
		fmt.Printf("Failed to log Gemini usage: %v\n", err)
	}
}

// sanitizeInput - Clean and validate user input
func sanitizeInput(input string) string {
	// Remove HTML tags and trim whitespace
	cleaned := html.EscapeString(strings.TrimSpace(input))

	// Limit message length
	if len(cleaned) > 1000 {
		cleaned = cleaned[:1000]
	}

	return cleaned
}

// checkRateLimit - Enhanced rate limiting with proper implementation
func checkRateLimit(userIP string) bool {
	// Initialize rate limiters if not already done
	if chatRateLimiter == nil {
		InitRateLimiters()
	}

	// Use chat rate limiter for message endpoints
	return chatRateLimiter.Allow(userIP)
}

// validateUserToken - Validate user authentication token
func validateUserToken(token string) (string, error) {
	// Simple token validation - implement proper JWT validation in production
	if len(token) < 24 {
		return "", fmt.Errorf("invalid token")
	}

	// Extract user ID from token (first 24 characters should be ObjectID)
	userID := token[:24]

	// Validate if it's a valid ObjectID
	_, err := primitive.ObjectIDFromHex(userID)
	if err != nil {
		return "", fmt.Errorf("invalid user ID in token")
	}

	return userID, nil
}

// RateMessage - Allow users to rate responses
func RateMessage(c *gin.Context) {
	messageID := c.Param("messageId")
	objID, err := primitive.ObjectIDFromHex(messageID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid message ID"})
		return
	}

	var rating struct {
		Rating   int    `json:"rating"` // 1-5 stars
		Feedback string `json:"feedback"`
	}

	if err := c.ShouldBindJSON(&rating); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid rating data"})
		return
	}

	if rating.Rating < 1 || rating.Rating > 5 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Rating must be between 1 and 5"})
		return
	}

	// Update message with rating
	collection := config.DB.Collection("chat_messages")
	_, err = collection.UpdateOne(
		context.Background(),
		bson.M{"_id": objID},
		bson.M{"$set": bson.M{
			"rating":   rating.Rating,
			"feedback": rating.Feedback,
			"rated_at": time.Now(),
		}},
	)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save rating"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Rating saved successfully"})
}

// calculateGeminiCost - Cost calculation function
func calculateGeminiCost(model string, inputTokens, outputTokens int) float64 {
	var inputCostPer1K, outputCostPer1K float64

	switch model {
	case "gemini-1.5-flash":
		inputCostPer1K = 0.000075 // $0.075 per 1K input tokens
		outputCostPer1K = 0.0003  // $0.30 per 1K output tokens
	case "gemini-1.5-pro":
		inputCostPer1K = 0.00125 // $1.25 per 1K input tokens
		outputCostPer1K = 0.005  // $5.00 per 1K output tokens
	default:
		inputCostPer1K = 0.000075 // Default to Flash pricing
		outputCostPer1K = 0.0003
	}

	inputCost := (float64(inputTokens) / 1000.0) * inputCostPer1K
	outputCost := (float64(outputTokens) / 1000.0) * outputCostPer1K

	return math.Round((inputCost+outputCost)*100000) / 100000
}

// getNextDailyReset - Reset time helpers
func getNextDailyReset() string {
	tomorrow := time.Now().AddDate(0, 0, 1).Truncate(24 * time.Hour)
	return tomorrow.Format(time.RFC3339)
}

// getNextMonthlyReset - Monthly reset helper
func getNextMonthlyReset() string {
	now := time.Now()
	nextMonth := time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, now.Location())
	return nextMonth.Format(time.RFC3339)
}

// estimateTokens - Helper function to estimate token count
func estimateTokens(text string) int {
	// Rough estimation: 1 token ≈ 4 characters for English text
	// This is an approximation since exact tokenization varies by model
	return len(text) / 4
}

// RateLimitMiddleware creates a rate limiting middleware for different endpoint types
func RateLimitMiddleware(limiterType string) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip rate limiting for OPTIONS requests (CORS preflight)
		if c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		clientIP := c.ClientIP()

		// Initialize rate limiters if not already done
		if chatRateLimiter == nil {
			InitRateLimiters()
		}

		var allowed bool
		var remaining int

		switch limiterType {
		case "chat":
			allowed = chatRateLimiter.Allow(clientIP)
			remaining = chatRateLimiter.GetRemainingRequests(clientIP)
		case "auth":
			allowed = authRateLimiter.Allow(clientIP)
			remaining = authRateLimiter.GetRemainingRequests(clientIP)
		case "general":
			allowed = generalRateLimiter.Allow(clientIP)
			remaining = generalRateLimiter.GetRemainingRequests(clientIP)
		default:
			allowed = generalRateLimiter.Allow(clientIP)
			remaining = generalRateLimiter.GetRemainingRequests(clientIP)
		}

		// Add rate limit headers
		c.Header("X-RateLimit-Remaining", fmt.Sprintf("%d", remaining))
		c.Header("X-RateLimit-Reset", fmt.Sprintf("%d", time.Now().Add(time.Minute).Unix()))

		if !allowed {
			c.Header("Retry-After", "60")
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":       "Rate limit exceeded",
				"message":     "Too many requests. Please wait before trying again.",
				"retry_after": 60,
				"remaining":   0,
				"limit_type":  limiterType,
			})
			c.Abort()
			return
		}

		c.Next()
	}
}

// CORSDebugMiddleware logs CORS-related information for debugging
// CORSDebugMiddleware provides CORS debugging information
func CORSDebugMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only debug in development mode
		if gin.Mode() == gin.DebugMode {
			origin := c.Request.Header.Get("Origin")
			method := c.Request.Method

			log.Printf("🔍 CORS Debug - Origin: %s, Method: %s, Path: %s",
				origin, method, c.Request.URL.Path)

			// Log CORS-related headers
			corsHeaders := []string{
				"Origin",
				"Access-Control-Request-Method",
				"Access-Control-Request-Headers",
				"Referer",
			}

			for _, header := range corsHeaders {
				if value := c.Request.Header.Get(header); value != "" {
					log.Printf("  %s: %s", header, value)
				}
			}
		}

		c.Next()
	}
}
