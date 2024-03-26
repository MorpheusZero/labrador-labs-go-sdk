package main

import (
	_ "github.com/joho/godotenv/autoload"
	"os"
	"testing"
)

func TestLabLabsClient_Authenticate(t *testing.T) {
	client := CreateLabLabsClient(os.Getenv("ORGANIZATION_ID"))

	// Authenticate Test
	err := client.Authenticate(os.Getenv("USERNAME"), os.Getenv("PASSWORD"))
	if err != nil {
		t.Errorf("[TEST] Authentication failed")
	}

	// Results Test
	results, err := client.GetMostRecentAnalyzeResultsForAllProjects()
	if err != nil {
		t.Errorf("[TEST] Get Results failed")
	}

	var size = len(results.Content)

	if size == 0 {
		t.Errorf("[TEST] Get Results should not be 0.")
	}
}
