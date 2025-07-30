package config

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

var GeminiClient *genai.Client

// ✅ Initialize Gemini client once
func InitGemini() {
	apiKey := os.Getenv("GEMINI_API_KEY")
	if apiKey == "" {
		log.Fatal("GEMINI_API_KEY not set in environment")
	}

	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		log.Fatal("❌ Failed to initialize Gemini client:", err)
	}

	GeminiClient = client
	log.Println("✅ Gemini client initialized successfully")
}

// ✅ Main function: Ask Gemini & return cleaned response
func GenerateResponse(userPrompt string, pdfContext string) (string, error) {
	ctx := context.Background()
	model := GeminiClient.GenerativeModel("gemini-2.0-flash")

	// Set model behavior
	model.SetTemperature(0.85)
	model.SetTopP(0.9)
	model.SetTopK(40)

	// Optional: Reduce over-filtering (safe in admin/internal apps)
	// model.SetSafetySettings([]genai.SafetySetting{
	// 	{Category: genai.HarmCategoryHarassment, Threshold: genai.BlockNone},
	// 	{Category: genai.HarmCategoryHateSpeech, Threshold: genai.BlockNone},
	// 	{Category: genai.HarmCategorySexuallyExplicit, Threshold: genai.BlockNone},
	// 	{Category: genai.HarmCategoryDangerousContent, Threshold: genai.BlockNone},
	// })

	// Add unique token to bypass prompt caching
	noise := fmt.Sprintf("<!-- v2.1 | %d -->", time.Now().UnixNano()%1000)

	// ✅ Final Prompt with tone and assistant instructions
	fullPrompt := fmt.Sprintf(`
You're a friendly and respectful assistant — reply like a smart friend would, not like a robot.

Give a short, helpful answer (1–2 lines max). Don’t mention context, background, or any documents.

Speak naturally, be polite, and don’t use robotic phrases.

Question: %s

Context: %s

%s
`, userPrompt, pdfContext, noise)

	// Request Gemini to generate content
	resp, err := model.GenerateContent(ctx, genai.Text(fullPrompt))
	if err != nil {
		log.Printf("❌ Gemini content generation failed: %v", err)
		return "", fmt.Errorf("failed to generate content: %v", err)
	}

	if len(resp.Candidates) > 0 && len(resp.Candidates[0].Content.Parts) > 0 {
		raw := string(resp.Candidates[0].Content.Parts[0].(genai.Text))
		clean := cleanResponse(raw)
		return clean, nil
	}

	return "No response generated", nil
}

// ✅ Removes robotic or repetitive phrases from Gemini response
func cleanResponse(raw string) string {
	cleaned := raw

	// Common Gemini disclaimers and robotic patterns
	patterns := []string{
		`(?i)^based on the .*?(document|pdf)[,:]?\s*`,
		`(?i)^according to .*?[,:]?\s*`,
		`(?i)^as per .*?[,:]?\s*`,
		`(?i)i am an ai.*`,
		`(?i)i'm not .*?but.*`,
		`(?i)let me know if you need anything else.*?`,
		`(?i)hope this helps[.!]?`,
		`(?i)i'm here to assist you.*?`,
		`(?i)is there anything else.*?\?$`,
	}

	for _, p := range patterns {
		cleaned = regexp.MustCompile(p).ReplaceAllString(cleaned, "")
	}

	// Clean leftover markdown like **bold** or *italic*
	cleaned = strings.ReplaceAll(cleaned, "**", "")
	cleaned = strings.ReplaceAll(cleaned, "*", "")

	// Trim spaces
	return strings.TrimSpace(cleaned)
}
