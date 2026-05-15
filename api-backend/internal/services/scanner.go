package services

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"os"

	"secretops/internal/crypto"
	"secretops/internal/models"
)

type ScannerService struct {
	db *sql.DB
}

func NewScannerService(db *sql.DB) *ScannerService {
	return &ScannerService{db: db}
}

func (s *ScannerService) RunScan(scanID int64, repo *models.Repository, branch string) {
	log.Printf("Starting scan %d for repo %s", scanID, repo.FullPath)

	// Get gitlab config
	var config, encSecrets string
	err := s.db.QueryRow(`SELECT config, COALESCE(encrypted_secrets,'') FROM integrations WHERE type='gitlab'`).Scan(&config, &encSecrets)
	if err != nil {
		s.failScan(scanID, "GitLab integration not configured")
		return
	}

	var configMap map[string]interface{}
	json.Unmarshal([]byte(config), &configMap)
	secrets := map[string]string{}
	if encSecrets != "" {
		if dec, err := crypto.Decrypt(encSecrets); err == nil {
			json.Unmarshal([]byte(dec), &secrets)
		}
	}

	gitlabURL, _ := configMap["url"].(string)
	token, _ := configMap["token"].(string)
	if token == "" {
		token = secrets["token"]
	}

	// Send scan request to AI engine
	payload := map[string]interface{}{
		"scan_id":     scanID,
		"repo_id":     repo.ID,
		"repo_path":   repo.FullPath,
		"repo_url":    repo.URL,
		"branch":      branch,
		"gitlab_url":  gitlabURL,
		"gitlab_token": token,
	}

	payloadBytes, _ := json.Marshal(payload)

	s.updateScanStage(scanID, "sending_to_engine")

	aiEngineURL := os.Getenv("AI_ENGINE_URL")
	if aiEngineURL == "" {
		aiEngineURL = "http://ai-engine:5001"
	}
	resp, err := http.Post(aiEngineURL+"/api/scan", "application/json", bytes.NewReader(payloadBytes))
	if err != nil {
		log.Printf("AI engine unreachable for scan %d: %v", scanID, err)
		s.failScan(scanID, fmt.Sprintf("AI engine unreachable: %v", err))
		return
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		s.failScan(scanID, fmt.Sprintf("AI engine error: %s", string(body)))
		return
	}

	// Poll for completion
	s.pollScanCompletion(scanID)
}

func (s *ScannerService) pollScanCompletion(scanID int64) {
	maxWait := 30 * time.Minute
	interval := 5 * time.Second
	deadline := time.Now().Add(maxWait)

	for time.Now().Before(deadline) {
		time.Sleep(interval)
		var status string
		s.db.QueryRow(`SELECT status FROM scans WHERE id=?`, scanID).Scan(&status)
		if status == "completed" || status == "failed" {
			return
		}
	}
	s.failScan(scanID, "Scan timed out")
}

func (s *ScannerService) updateScanStage(scanID int64, stage string) {
	s.db.Exec(`UPDATE scans SET stage=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, stage, scanID)
}

func (s *ScannerService) failScan(scanID int64, msg string) {
	s.db.Exec(`UPDATE scans SET status='failed', stage='failed', error_message=?, completed_at=CURRENT_TIMESTAMP WHERE id=?`, msg, scanID)
}
