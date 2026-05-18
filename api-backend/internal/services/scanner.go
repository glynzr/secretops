package services

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

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

	// Get SCM config — try gitlab, then github, based on repo provider
	provider := repo.Provider
	if provider == "" {
		provider = "gitlab"
	}

	var config, encSecrets string
	err := s.db.QueryRow(`SELECT config, COALESCE(encrypted_secrets,'') FROM integrations WHERE type=?`, provider).Scan(&config, &encSecrets)
	if err != nil {
		// Fallback: try any SCM integration
		err = s.db.QueryRow(`SELECT config, COALESCE(encrypted_secrets,'') FROM integrations WHERE type IN ('gitlab','github') LIMIT 1`).Scan(&config, &encSecrets)
		if err != nil {
			s.failScan(scanID, "No SCM integration configured (GitLab or GitHub)")
			return
		}
	}

	var configMap map[string]interface{}
	json.Unmarshal([]byte(config), &configMap)
	secrets := map[string]string{}
	if encSecrets != "" {
		if dec, err := crypto.Decrypt(encSecrets); err == nil {
			json.Unmarshal([]byte(dec), &secrets)
		}
	}

	scmURL, _ := configMap["url"].(string)
	if scmURL == "" && provider == "github" {
		scmURL = "https://github.com"
	}
	token, _ := configMap["token"].(string)
	if token == "" {
		token = secrets["token"]
	}

	// Send to AI engine
	payload := map[string]interface{}{
		"scan_id":      scanID,
		"repo_id":      repo.ID,
		"repo_path":    repo.FullPath,
		"repo_url":     repo.URL,
		"branch":       branch,
		"gitlab_url":   scmURL,
		"gitlab_token": token,
		"provider":     provider,
	}

	payloadBytes, _ := json.Marshal(payload)
	aiEngineURL := os.Getenv("AI_ENGINE_URL")
	if aiEngineURL == "" {
		aiEngineURL = "http://ai-engine:5001"
	}

	resp, err := http.Post(aiEngineURL+"/api/scan", "application/json", bytes.NewReader(payloadBytes))
	if err != nil {
		s.failScan(scanID, fmt.Sprintf("AI engine unreachable: %v", err))
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		s.failScan(scanID, fmt.Sprintf("AI engine error: %s", string(body)))
		return
	}

	// Poll for completion then send Slack summary
	s.pollScanCompletion(scanID)
	s.sendScanCompletionSlack(scanID, repo)
}

func (s *ScannerService) pollScanCompletion(scanID int64) {
	deadline := time.Now().Add(30 * time.Minute)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		var status string
		s.db.QueryRow(`SELECT status FROM scans WHERE id=?`, scanID).Scan(&status)
		if status == "completed" || status == "failed" {
			return
		}
	}
	s.failScan(scanID, "Scan timed out")
}

func (s *ScannerService) sendScanCompletionSlack(scanID int64, repo *models.Repository) {
	// Get scan results
	var status, stage string
	var totalFiles, findingsCount int
	s.db.QueryRow(`SELECT status, stage, total_files, findings_count FROM scans WHERE id=?`, scanID).
		Scan(&status, &stage, &totalFiles, &findingsCount)

	// Get severity breakdown
	rows, _ := s.db.Query(`SELECT severity, COUNT(*) FROM findings WHERE scan_id=? GROUP BY severity`, scanID)
	severities := map[string]int{}
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var cnt int
			rows.Scan(&sev, &cnt)
			severities[sev] = cnt
		}
	}

	// Get Slack webhook
	var slackConfig string
	if err := s.db.QueryRow(`SELECT config FROM integrations WHERE type='slack'`).Scan(&slackConfig); err != nil {
		return
	}
	var slackMap map[string]interface{}
	json.Unmarshal([]byte(slackConfig), &slackMap)
	webhook, _ := slackMap["webhook_url"].(string)
	if webhook == "" {
		return
	}

	// Build severity summary string
	parts := []string{}
	for _, sev := range []string{"critical", "high", "medium", "low"} {
		if cnt, ok := severities[sev]; ok && cnt > 0 {
			emoji := map[string]string{"critical": "🚨", "high": "⚠️", "medium": "🔶", "low": "ℹ️"}[sev]
			parts = append(parts, fmt.Sprintf("%s %d %s", emoji, cnt, sev))
		}
	}
	sevStr := "None"
	if len(parts) > 0 {
		sevStr = strings.Join(parts, "  |  ")
	}

	statusEmoji := "✅"
	if status == "failed" {
		statusEmoji = "❌"
	} else if findingsCount > 0 {
		statusEmoji = "🔍"
	}

	blocks := []map[string]interface{}{
		{
			"type": "header",
			"text": map[string]interface{}{
				"type": "plain_text",
				"text": fmt.Sprintf("%s SecretOps: Scan Complete — %s", statusEmoji, repo.Name),
			},
		},
		{
			"type": "section",
			"fields": []map[string]interface{}{
				{"type": "mrkdwn", "text": fmt.Sprintf("*Repository:*\n`%s`", repo.FullPath)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Status:*\n%s", status)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Files Scanned:*\n%d", totalFiles)},
				{"type": "mrkdwn", "text": fmt.Sprintf("*Findings:*\n%d", findingsCount)},
			},
		},
	}

	if findingsCount > 0 {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": fmt.Sprintf("*Severity Breakdown:*\n%s", sevStr),
			},
		})
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{
				"type": "mrkdwn",
				"text": "⚡ *Action required:* Review findings in SecretOps and click Remediate on confirmed secrets.",
			},
		})
	} else {
		blocks = append(blocks, map[string]interface{}{
			"type": "section",
			"text": map[string]interface{}{"type": "mrkdwn", "text": "✨ No secrets detected in this scan."},
		})
	}

	payload, _ := json.Marshal(map[string]interface{}{
		"text":   fmt.Sprintf("%s Scan complete for %s: %d findings", statusEmoji, repo.FullPath, findingsCount),
		"blocks": blocks,
	})

	resp, err := http.Post(webhook, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Printf("Slack notification failed: %v", err)
		return
	}
	defer resp.Body.Close()
	log.Printf("Slack scan summary sent for scan %d (status %d)", scanID, resp.StatusCode)
}

func (s *ScannerService) failScan(scanID int64, msg string) {
	s.db.Exec(`UPDATE scans SET status='failed', stage='failed', error_message=?, completed_at=CURRENT_TIMESTAMP WHERE id=?`, msg, scanID)
}
