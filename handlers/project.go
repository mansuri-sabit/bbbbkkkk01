package handlers

import (
    "context"
    "fmt"
    "net/http"
    "os"
    "path/filepath"
    "strings"
    "time"
    
    "github.com/gin-gonic/gin"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/bson/primitive"
    "github.com/google/generative-ai-go/genai"
    "google.golang.org/api/option"
    "jevi-chat/config"
    "jevi-chat/models"
)

// ===== PDF MANAGEMENT =====

// UploadPDF - Enhanced PDF upload with multiple file support
func UploadPDF(c *gin.Context) {
    projectID := c.Param("id")
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }

    // Get project to check if it exists
    collection := config.DB.Collection("projects")
    var project models.Project
    err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&project)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
        return
    }

    // Handle multiple file upload
    form, err := c.MultipartForm()
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Failed to parse form"})
        return
    }

    files := form.File["pdfs"]
    if len(files) == 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "No files uploaded"})
        return
    }

    var uploadedFiles []models.PDFFile
    var allContent strings.Builder

    // Create uploads directory if it doesn't exist
    os.MkdirAll("./static/uploads", 0755)

    for _, file := range files {
        // Validate file type and size
        if !strings.HasSuffix(strings.ToLower(file.Filename), ".pdf") {
            continue
        }
        if file.Size > 10*1024*1024 { // 10MB limit
            continue
        }

        // Generate unique filename
        fileID := primitive.NewObjectID().Hex()
        fileName := fmt.Sprintf("%s_%s", fileID, file.Filename)
        filePath := fmt.Sprintf("./static/uploads/%s", fileName)

        // Save file
        if err := c.SaveUploadedFile(file, filePath); err != nil {
            continue
        }

        pdfFile := models.PDFFile{
            ID:         fileID,
            FileName:   file.Filename,
            FilePath:   filePath,
            FileSize:   file.Size,
            UploadedAt: time.Now(),
            Status:     "processing",
        }

        // Process with Gemini if enabled
        var content string
        if project.GeminiEnabled && project.GeminiAPIKey != "" {
            content, err = processPDFWithGemini(filePath, project.GeminiAPIKey, project.GeminiModel)

            if err == nil {
                pdfFile.ProcessedAt = time.Now()
                pdfFile.Status = "completed"
            } else {
                pdfFile.Status = "failed"
                content = "Failed to process PDF content"
            }
        } else {
            content = "PDF uploaded successfully (Gemini processing disabled)"
            pdfFile.Status = "completed"
        }

        uploadedFiles = append(uploadedFiles, pdfFile)
        allContent.WriteString(content + "\n\n")
    }

    // Update project with PDF files and content
    update := bson.M{
        "$push": bson.M{"pdf_files": bson.M{"$each": uploadedFiles}},
        "$set": bson.M{
            "pdf_content": allContent.String(),
            "updated_at":  time.Now(),
        },
    }

    _, err = collection.UpdateOne(context.Background(), bson.M{"_id": objID}, update)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update project"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message":        "PDFs uploaded and processed successfully",
        "files_uploaded": len(uploadedFiles),
        "files":          uploadedFiles,
    })
}

// processPDFWithGemini - Enhanced PDF processing with Gemini AI
func processPDFWithGemini(filePath, apiKey, modelName string) (string, error) {
    ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
    defer cancel()

    client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
    if err != nil {
        return "", fmt.Errorf("failed to create Gemini client: %v", err)
    }
    defer client.Close()

    file, err := client.UploadFileFromPath(ctx, filePath, nil)
    if err != nil {
        return "", fmt.Errorf("failed to upload file to Gemini: %v", err)
    }

    maxWaitTime := 30 * time.Second
    startTime := time.Now()

    for file.State == genai.FileStateProcessing {
        if time.Since(startTime) > maxWaitTime {
            return "", fmt.Errorf("file processing timeout")
        }
        time.Sleep(2 * time.Second)
        file, err = client.GetFile(ctx, file.Name)
        if err != nil {
            return "", fmt.Errorf("failed to check file status: %v", err)
        }
    }

    if file.State != genai.FileStateActive {
        return "", fmt.Errorf("file processing failed with state: %v", file.State)
    }

    model := client.GenerativeModel(modelName) // ✅ dynamic model
    resp, err := model.GenerateContent(ctx,
        genai.FileData{URI: file.URI, MIMEType: file.MIMEType},
        genai.Text(`Extract and organize all information from this document in a structured format...`),
    )
    if err != nil {
        return "", fmt.Errorf("failed to generate content: %v", err)
    }

    if len(resp.Candidates) > 0 && len(resp.Candidates[0].Content.Parts) > 0 {
        return string(resp.Candidates[0].Content.Parts[0].(genai.Text)), nil
    }

    return "", fmt.Errorf("no content generated from PDF")
}


// DeletePDF - Delete specific PDF file
func DeletePDF(c *gin.Context) {
    projectID := c.Param("id")
    fileID := c.Param("fileId")
    
    objID, err := primitive.ObjectIDFromHex(projectID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid project ID"})
        return
    }

    collection := config.DB.Collection("projects")
    
    // Get project to find file path for deletion
    var project models.Project
    err = collection.FindOne(context.Background(), bson.M{"_id": objID}).Decode(&project)
    if err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "Project not found"})
        return
    }
    
    // Find and delete physical file
    var fileToDelete models.PDFFile
    for _, file := range project.PDFFiles {
        if file.ID == fileID {
            fileToDelete = file
            break
        }
    }
    
    if fileToDelete.FilePath != "" {
        os.Remove(fileToDelete.FilePath)
    }
    
    // Remove file from array
    update := bson.M{
        "$pull": bson.M{"pdf_files": bson.M{"id": fileID}},
        "$set":  bson.M{"updated_at": time.Now()},
    }

    _, err = collection.UpdateOne(context.Background(), bson.M{"_id": objID}, update)
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete PDF"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "message": "PDF deleted successfully",
        "file_id": fileID,
    })
}

// GetPDFFiles - Get all PDF files for a project
func GetPDFFiles(c *gin.Context) {
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
        "project_id": projectID,
        "pdf_files":  project.PDFFiles,
        "total_files": len(project.PDFFiles),
    })
}

// ===== ANALYTICS =====

// ===== PROJECT DASHBOARD FUNCTIONS =====

// ProjectDashboard - Display project dashboard page
func ProjectDashboard(c *gin.Context) {
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
    
    // Get additional statistics
    chatCollection := config.DB.Collection("chat_messages")
    messageCount, _ := chatCollection.CountDocuments(context.Background(), bson.M{"project_id": objID})
    
    c.HTML(http.StatusOK, "project/dashboard.html", gin.H{
        "title":         "Project Dashboard - " + project.Name,
        "project":       project,
        "message_count": messageCount,
        "embed_url":     fmt.Sprintf("/embed/%s", projectID),
    })
}

// GetProjectInfo - Get project information for API calls
func GetProjectInfo(c *gin.Context) {
    projectID := c.Param("projectId")
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

    // Get additional stats
    chatCollection := config.DB.Collection("chat_messages")
    messageCount, _ := chatCollection.CountDocuments(context.Background(), bson.M{"project_id": objID})
    
    // Get unique sessions count
    pipeline := []bson.M{
        {"$match": bson.M{"project_id": objID}},
        {"$group": bson.M{"_id": "$session_id"}},
        {"$count": "unique_sessions"},
    }
    
    cursor, _ := chatCollection.Aggregate(context.Background(), pipeline)
    var result []bson.M
    cursor.All(context.Background(), &result)
    
    uniqueSessions := int64(0)
    if len(result) > 0 {
        if count, ok := result[0]["unique_sessions"].(int32); ok {
            uniqueSessions = int64(count)
        }
    }

    c.JSON(http.StatusOK, gin.H{
        "project_id":      projectID,
        "project":         project,
        "message_count":   messageCount,
        "unique_sessions": uniqueSessions,
        "embed_url":       fmt.Sprintf("/embed/%s", projectID),
    })
}

// ===== USER PROJECT FUNCTIONS =====

// UserProjects - Get projects for regular users
func UserProjects(c *gin.Context) {
    // Get user projects (implement based on your auth system)
    collection := config.DB.Collection("projects")
    
    // For now, return all active projects
    // In production, filter by user permissions
    cursor, err := collection.Find(context.Background(), bson.M{"is_active": true})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch projects"})
        return
    }

    var projects []models.Project
    if err := cursor.All(context.Background(), &projects); err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to parse projects"})
        return
    }

    c.JSON(http.StatusOK, gin.H{
        "projects": projects,
        "count":    len(projects),
    })
}

// ===== HELPER FUNCTIONS =====

// getGeminiModel - Get Gemini model with fallback
func getGeminiModel(model string) string {
    if model == "" {
        return "gemini-1.5-flash"
    }
    
    // Validate model name
    validModels := []string{"gemini-1.5-flash", "gemini-1.5-pro", "gemini-pro"}
    for _, validModel := range validModels {
        if model == validModel {
            return model
        }
    }
    
    return "gemini-1.5-flash" // fallback
}

// getWelcomeMessage - Get welcome message with fallback
func getWelcomeMessage(message string) string {
    if message == "" {
        return "Hello! How can I help you today?"
    }
    return message
}

// validateFileType - Validate uploaded file type
func validateFileType(filename string) bool {
    allowedExtensions := []string{".pdf", ".doc", ".docx", ".txt"}
    ext := strings.ToLower(filepath.Ext(filename))
    
    for _, allowed := range allowedExtensions {
        if ext == allowed {
            return true
        }
    }
    return false
}

// formatFileSize - Format file size for display
func formatFileSize(bytes int64) string {
    const unit = 1024
    if bytes < unit {
        return fmt.Sprintf("%d B", bytes)
    }
    div, exp := int64(unit), 0
    for n := bytes / unit; n >= unit; n /= unit {
        div *= unit
        exp++
    }
    return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

