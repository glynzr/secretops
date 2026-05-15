package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"secretops/internal/crypto"
	"secretops/internal/models"
	"secretops/internal/services"
)

type Handler struct {
	db      *sql.DB
	scanner *services.ScannerService
}

func NewHandler(db *sql.DB) *Handler {
	return &Handler{
		db:      db,
		scanner: services.NewScannerService(db),
	}
}

// ---- Integrations ----

func (h *Handler) GetIntegrations(c *gin.Context) {
	rows, err := h.db.Query(`SELECT id, type, config, status, last_tested_at, created_at, updated_at FROM integrations`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var integrations []models.Integration
	for rows.Next() {
		var i models.Integration
		if err := rows.Scan(&i.ID, &i.Type, &i.Config, &i.Status, &i.LastTestedAt, &i.CreatedAt, &i.UpdatedAt); err != nil {
			continue
		}
		i.Provider = i.Type // expose as "provider" for frontend
		integrations = append(integrations, i)
	}
	if integrations == nil {
		integrations = []models.Integration{}
	}
	c.JSON(200, integrations)
}

func (h *Handler) SaveIntegration(c *gin.Context) {
	var req struct {
		Type     string                 `json:"type"`
		Provider string                 `json:"provider"`
		Config   map[string]interface{} `json:"config"`
		Secrets  map[string]string      `json:"secrets"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	// Accept either "type" or "provider" field from frontend
	if req.Type == "" {
		req.Type = req.Provider
	}
	if req.Type == "" {
		c.JSON(400, gin.H{"error": "type or provider is required"})
		return
	}

	configJSON, _ := json.Marshal(req.Config)
	encryptedSecrets := ""
	if len(req.Secrets) > 0 {
		secretsJSON, _ := json.Marshal(req.Secrets)
		var err error
		encryptedSecrets, err = crypto.Encrypt(string(secretsJSON))
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to encrypt secrets"})
			return
		}
	}

	_, err := h.db.Exec(`
		INSERT INTO integrations (type, config, encrypted_secrets, status, updated_at)
		VALUES (?, ?, ?, 'untested', CURRENT_TIMESTAMP)
		ON CONFLICT(type) DO UPDATE SET
			config=excluded.config,
			encrypted_secrets=CASE WHEN excluded.encrypted_secrets != '' THEN excluded.encrypted_secrets ELSE encrypted_secrets END,
			status='untested',
			updated_at=CURRENT_TIMESTAMP
	`, req.Type, string(configJSON), encryptedSecrets)

	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	h.logAudit("integration.saved", "integration", 0, fmt.Sprintf("type=%s", req.Type))

	// Run a live test and return status so the frontend Save & Test button works
	var savedConfig string
	var savedSecrets string
	h.db.QueryRow(`SELECT config, COALESCE(encrypted_secrets,'') FROM integrations WHERE type=?`, req.Type).Scan(&savedConfig, &savedSecrets)
	var configMap map[string]interface{}
	json.Unmarshal([]byte(savedConfig), &configMap)
	secrets := map[string]string{}
	if savedSecrets != "" {
		if dec, err2 := crypto.Decrypt(savedSecrets); err2 == nil {
			json.Unmarshal([]byte(dec), &secrets)
		}
	}
	result := h.testIntegrationConnection(req.Type, configMap, secrets)
	status := "connected"
	if !result.Success {
		status = "error"
	}
	h.db.Exec(`UPDATE integrations SET status=?, last_tested_at=CURRENT_TIMESTAMP WHERE type=?`, status, req.Type)
	c.JSON(200, gin.H{"status": status, "message": result.Message, "provider": req.Type})
}

func (h *Handler) TestIntegration(c *gin.Context) {
	intType := c.Param("type")

	var config string
	var encryptedSecrets string
	err := h.db.QueryRow(`SELECT config, COALESCE(encrypted_secrets,'') FROM integrations WHERE type=?`, intType).Scan(&config, &encryptedSecrets)
	if err != nil {
		c.JSON(404, gin.H{"error": "Integration not found"})
		return
	}

	var configMap map[string]interface{}
	json.Unmarshal([]byte(config), &configMap)

	secrets := map[string]string{}
	if encryptedSecrets != "" {
		if dec, err := crypto.Decrypt(encryptedSecrets); err == nil {
			json.Unmarshal([]byte(dec), &secrets)
		}
	}

	result := h.testIntegrationConnection(intType, configMap, secrets)

	status := "connected"
	if !result.Success {
		status = "error"
	}

	h.db.Exec(`UPDATE integrations SET status=?, last_tested_at=CURRENT_TIMESTAMP WHERE type=?`, status, intType)

	if result.Success {
		c.JSON(200, gin.H{"success": true, "message": result.Message})
	} else {
		c.JSON(400, gin.H{"success": false, "error": result.Message})
	}
}

type testResult struct {
	Success bool
	Message string
}

func (h *Handler) testIntegrationConnection(intType string, config map[string]interface{}, secrets map[string]string) testResult {
	switch intType {
	case "gitlab":
		url, _ := config["url"].(string)
		token, _ := config["token"].(string)
		if token == "" {
			token = secrets["token"]
		}
		if url == "" || token == "" {
			return testResult{false, "GitLab URL and token required"}
		}
		req, _ := http.NewRequest("GET", strings.TrimRight(url, "/")+"/api/v4/user", nil)
		req.Header.Set("PRIVATE-TOKEN", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return testResult{false, fmt.Sprintf("Connection failed: %v", err)}
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			return testResult{true, "GitLab connection successful"}
		}
		return testResult{false, fmt.Sprintf("GitLab returned status %d", resp.StatusCode)}

	case "vault":
		addr, _ := config["url"].(string)
		if addr == "" {
			addr, _ = config["address"].(string)
		}
		token, _ := config["token"].(string)
		if token == "" {
			token = secrets["token"]
		}
		if addr == "" || token == "" {
			return testResult{false, "Vault address and token required"}
		}
		req, _ := http.NewRequest("GET", strings.TrimRight(addr, "/")+"/v1/sys/health", nil)
		req.Header.Set("X-Vault-Token", token)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			return testResult{false, fmt.Sprintf("Connection failed: %v", err)}
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 || resp.StatusCode == 429 || resp.StatusCode == 473 {
			return testResult{true, "Vault connection successful"}
		}
		return testResult{false, fmt.Sprintf("Vault returned status %d", resp.StatusCode)}

	case "slack":
		webhookURL, _ := config["webhook_url"].(string)
		if webhookURL == "" {
			webhookURL = secrets["webhook_url"]
		}
		if webhookURL == "" {
			return testResult{false, "Slack webhook URL required"}
		}
		payload := `{"text":"✅ SecretOps test notification — connection successful!"}`
		resp, err := http.Post(webhookURL, "application/json", strings.NewReader(payload))
		if err != nil {
			return testResult{false, fmt.Sprintf("Connection failed: %v", err)}
		}
		defer resp.Body.Close()
		if resp.StatusCode == 200 {
			return testResult{true, "Slack webhook verified — test message sent"}
		}
		return testResult{false, fmt.Sprintf("Slack returned status %d", resp.StatusCode)}

	case "openai", "anthropic", "groq":
		apiKey, _ := config["api_key"].(string)
		if apiKey == "" {
			apiKey = secrets["api_key"]
		}
		if apiKey == "" {
			return testResult{false, "API key required"}
		}
		// Forward test to AI engine
		aiEngineURL := os.Getenv("AI_ENGINE_URL")
		if aiEngineURL == "" { aiEngineURL = "http://ai-engine:5001" }
		aiURL := aiEngineURL + "/api/test-provider"
		payload, _ := json.Marshal(map[string]string{"provider": intType, "api_key": apiKey})
		resp, err := http.Post(aiURL, "application/json", strings.NewReader(string(payload)))
		if err != nil {
			// AI engine unreachable — save key and trust format check
			if len(apiKey) > 10 {
				return testResult{true, fmt.Sprintf("%s API key saved (live test skipped: AI engine offline)", intType)}
			}
			return testResult{false, "API key too short"}
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)
		if resp.StatusCode == 200 {
			return testResult{true, fmt.Sprintf("%s connected successfully", intType)}
		}
		// Extract message from AI engine response
		var aiResp map[string]interface{}
		json.Unmarshal(respBody, &aiResp)
		msg := ""
		if m, ok := aiResp["message"].(string); ok {
			msg = m
		} else if m, ok := aiResp["error"].(string); ok {
			msg = m
		}
		if msg == "" {
			msg = fmt.Sprintf("status %d", resp.StatusCode)
		}
		return testResult{false, msg}

	case "ollama":
		baseURL, _ := config["api_key"].(string) // reusing api_key field for base URL
		if baseURL == "" {
			baseURL = "http://localhost:11434"
		}
		return testResult{true, fmt.Sprintf("Ollama endpoint saved: %s", baseURL)}

	case "smtp":
		host, _ := config["host"].(string)
		if host == "" {
			return testResult{false, "SMTP host required"}
		}
		return testResult{true, "SMTP configuration saved"}
	}

	return testResult{true, "Integration saved"}
}

func (h *Handler) DeleteIntegration(c *gin.Context) {
	intType := c.Param("type")
	h.db.Exec(`DELETE FROM integrations WHERE type=?`, intType)
	c.JSON(200, gin.H{"message": "Deleted"})
}

// ---- Repositories ----

func (h *Handler) GetRepositories(c *gin.Context) {
	rows, _ := h.db.Query(`SELECT id, COALESCE(gitlab_id,0), name, full_path, url, default_branch, last_scanned_at, created_at FROM repositories ORDER BY created_at DESC`)
	defer rows.Close()
	var repos []models.Repository
	for rows.Next() {
		var r models.Repository
		rows.Scan(&r.ID, &r.GitlabID, &r.Name, &r.FullPath, &r.URL, &r.DefaultBranch, &r.LastScannedAt, &r.CreatedAt)
		repos = append(repos, r)
	}
	if repos == nil {
		repos = []models.Repository{}
	}
	c.JSON(200, repos)
}

func (h *Handler) ListGitLabRepositories(c *gin.Context) {
	var config string
	var encSecrets string
	err := h.db.QueryRow(`SELECT config, COALESCE(encrypted_secrets,'') FROM integrations WHERE type='gitlab'`).Scan(&config, &encSecrets)
	if err != nil {
		c.JSON(400, gin.H{"error": "GitLab integration not configured"})
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

	if gitlabURL == "" || token == "" {
		c.JSON(400, gin.H{"error": "GitLab URL or token missing — re-save the GitLab integration"})
		return
	}

	req, _ := http.NewRequest("GET", strings.TrimRight(gitlabURL, "/")+"/api/v4/projects?membership=true&per_page=100&order_by=last_activity_at&simple=true", nil)
	req.Header.Set("PRIVATE-TOKEN", token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.JSON(500, gin.H{"error": fmt.Sprintf("GitLab request failed: %v", err)})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		c.JSON(resp.StatusCode, gin.H{"error": fmt.Sprintf("GitLab returned %d: %s", resp.StatusCode, string(body))})
		return
	}
	var projects []map[string]interface{}
	json.Unmarshal(body, &projects)
	if projects == nil {
		projects = []map[string]interface{}{}
	}
	c.JSON(200, projects)
}

func (h *Handler) AddRepository(c *gin.Context) {
	var req struct {
		GitlabID      int64  `json:"gitlab_id"`
		Name          string `json:"name"`
		FullPath      string `json:"full_path"`
		URL           string `json:"url"`
		DefaultBranch string `json:"default_branch"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if req.DefaultBranch == "" {
		req.DefaultBranch = "main"
	}
	res, err := h.db.Exec(`INSERT OR IGNORE INTO repositories (gitlab_id,name,full_path,url,default_branch) VALUES (?,?,?,?,?)`,
		req.GitlabID, req.Name, req.FullPath, req.URL, req.DefaultBranch)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	id, _ := res.LastInsertId()
	c.JSON(201, gin.H{"id": id, "message": "Repository added"})
}

// ---- Scans ----

func (h *Handler) StartScan(c *gin.Context) {
	var req struct {
		RepositoryID int64  `json:"repository_id" binding:"required"`
		Branch       string `json:"branch"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}

	var repo models.Repository
	err := h.db.QueryRow(`SELECT id, name, full_path, url, default_branch FROM repositories WHERE id=?`, req.RepositoryID).
		Scan(&repo.ID, &repo.Name, &repo.FullPath, &repo.URL, &repo.DefaultBranch)
	if err != nil {
		c.JSON(404, gin.H{"error": "Repository not found"})
		return
	}

	if req.Branch == "" {
		req.Branch = repo.DefaultBranch
	}

	res, err := h.db.Exec(`INSERT INTO scans (repository_id, status, stage) VALUES (?, 'running', 'cloning')`, req.RepositoryID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	scanID, _ := res.LastInsertId()

	// Dispatch to AI engine asynchronously
	go h.scanner.RunScan(scanID, &repo, req.Branch)

	c.JSON(201, gin.H{"scan_id": scanID, "status": "started"})
}

func (h *Handler) GetScan(c *gin.Context) {
	id := c.Param("id")
	var s models.Scan
	err := h.db.QueryRow(`SELECT id, repository_id, status, stage, total_files, scanned_files, findings_count, started_at, completed_at, COALESCE(error_message,'') FROM scans WHERE id=?`, id).
		Scan(&s.ID, &s.RepositoryID, &s.Status, &s.Stage, &s.TotalFiles, &s.ScannedFiles, &s.FindingsCount, &s.StartedAt, &s.CompletedAt, &s.ErrorMessage)
	if err != nil {
		c.JSON(404, gin.H{"error": "Scan not found"})
		return
	}
	c.JSON(200, s)
}

func (h *Handler) StreamScanStatus(c *gin.Context) {
	id := c.Param("id")
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	done := c.Request.Context().Done()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			var s models.Scan
			err := h.db.QueryRow(`SELECT id, repository_id, status, stage, total_files, scanned_files, findings_count, started_at, completed_at, COALESCE(error_message,'') FROM scans WHERE id=?`, id).
				Scan(&s.ID, &s.RepositoryID, &s.Status, &s.Stage, &s.TotalFiles, &s.ScannedFiles, &s.FindingsCount, &s.StartedAt, &s.CompletedAt, &s.ErrorMessage)
			if err != nil {
				return
			}
			data, _ := json.Marshal(s)
			fmt.Fprintf(c.Writer, "data: %s\n\n", data)
			c.Writer.Flush()
			if s.Status == "completed" || s.Status == "failed" {
				return
			}
		}
	}
}

// ---- Findings ----

func (h *Handler) GetFindings(c *gin.Context) {
	query := `SELECT id, scan_id, repository_id, file_path, line_number, secret_type, raw_value_hash, COALESCE(masked_value,''), ai_confidence, COALESCE(ai_reasoning,''), COALESCE(ai_model,''), severity, status, COALESCE(detection_stage,''), COALESCE(first_commit_hash,''), COALESCE(first_commit_author,''), first_commit_date, total_commits, days_exposed, COALESCE(vault_path,''), vault_poisoned, COALESCE(mr_url,''), COALESCE(mr_id,''), COALESCE(issue_url,''), COALESCE(branch_name,''), remediation_status, revoked, rotation_confirmed, created_at, updated_at FROM findings WHERE 1=1`
	args := []interface{}{}

	if status := c.Query("status"); status != "" {
		query += " AND status=?"
		args = append(args, status)
	}
	if repoID := c.Query("repository_id"); repoID != "" {
		query += " AND repository_id=?"
		args = append(args, repoID)
	}
	if scanID := c.Query("scan_id"); scanID != "" {
		query += " AND scan_id=?"
		args = append(args, scanID)
	}
	if severity := c.Query("severity"); severity != "" {
		query += " AND severity=?"
		args = append(args, severity)
	}
	query += " ORDER BY created_at DESC"
	if limit := c.Query("limit"); limit != "" {
		query += " LIMIT " + limit
	}

	rows, err := h.db.Query(query, args...)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var findings []models.Finding
	for rows.Next() {
		var f models.Finding
		rows.Scan(&f.ID, &f.ScanID, &f.RepositoryID, &f.FilePath, &f.LineNumber,
			&f.SecretType, &f.RawValueHash, &f.MaskedValue, &f.AIConfidence, &f.AIReasoning,
			&f.AIModel, &f.Severity, &f.Status, &f.DetectionStage, &f.FirstCommitHash,
			&f.FirstCommitAuthor, &f.FirstCommitDate, &f.TotalCommits, &f.DaysExposed,
			&f.VaultPath, &f.VaultPoisoned, &f.MrURL, &f.MrID, &f.IssueURL, &f.BranchName,
			&f.RemediationStatus, &f.Revoked, &f.RotationConfirmed, &f.CreatedAt, &f.UpdatedAt)
		findings = append(findings, f)
	}
	if findings == nil {
		findings = []models.Finding{}
	}
	c.JSON(200, findings)
}

func (h *Handler) GetFinding(c *gin.Context) {
	id := c.Param("id")
	var f models.Finding
	err := h.db.QueryRow(`SELECT id, scan_id, repository_id, file_path, line_number, secret_type, raw_value_hash, COALESCE(masked_value,''), ai_confidence, COALESCE(ai_reasoning,''), COALESCE(ai_model,''), severity, status, COALESCE(detection_stage,''), COALESCE(first_commit_hash,''), COALESCE(first_commit_author,''), first_commit_date, total_commits, days_exposed, COALESCE(vault_path,''), vault_poisoned, COALESCE(mr_url,''), COALESCE(mr_id,''), COALESCE(issue_url,''), COALESCE(branch_name,''), remediation_status, revoked, rotation_confirmed, created_at, updated_at FROM findings WHERE id=?`, id).
		Scan(&f.ID, &f.ScanID, &f.RepositoryID, &f.FilePath, &f.LineNumber,
			&f.SecretType, &f.RawValueHash, &f.MaskedValue, &f.AIConfidence, &f.AIReasoning,
			&f.AIModel, &f.Severity, &f.Status, &f.DetectionStage, &f.FirstCommitHash,
			&f.FirstCommitAuthor, &f.FirstCommitDate, &f.TotalCommits, &f.DaysExposed,
			&f.VaultPath, &f.VaultPoisoned, &f.MrURL, &f.MrID, &f.IssueURL, &f.BranchName,
			&f.RemediationStatus, &f.Revoked, &f.RotationConfirmed, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		c.JSON(404, gin.H{"error": "Finding not found"})
		return
	}
	c.JSON(200, f)
}

func (h *Handler) UpdateFindingStatus(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Status string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	validStatuses := map[string]bool{"open": true, "confirmed": true, "false_positive": true, "ignored": true, "closed": true}
	if !validStatuses[req.Status] {
		c.JSON(400, gin.H{"error": "Invalid status"})
		return
	}
	h.db.Exec(`UPDATE findings SET status=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, req.Status, id)
	h.logAudit("finding.status_updated", "finding", mustParseInt(id), fmt.Sprintf("status=%s", req.Status))
	c.JSON(200, gin.H{"message": "Status updated"})
}

func (h *Handler) TriggerRemediation(c *gin.Context) {
	id := c.Param("id")

	// Mark as confirmed + remediating
	h.db.Exec(`UPDATE findings SET status='confirmed', remediation_status='in_progress', updated_at=CURRENT_TIMESTAMP WHERE id=?`, id)
	h.logAudit("finding.remediation_triggered", "finding", mustParseInt(id), "")

	// Forward to AI engine
	aiBase := os.Getenv("AI_ENGINE_URL"); if aiBase == "" { aiBase = "http://ai-engine:5001" }
	resp, err := http.Post(fmt.Sprintf(aiBase+"/api/remediate/%s", id), "application/json", nil)
	if err != nil {
		// Queue as job if AI engine unreachable
		h.db.Exec(`INSERT INTO jobs (type, status, payload) VALUES ('remediation', 'pending', ?)`, fmt.Sprintf(`{"finding_id":%s}`, id))
		c.JSON(202, gin.H{"message": "Remediation queued"})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	c.Data(resp.StatusCode, "application/json", body)
}

func (h *Handler) GetFindingHistory(c *gin.Context) {
	id := c.Param("id")
	rows, _ := h.db.Query(`SELECT id, action, details, created_at FROM audit_logs WHERE entity_type='finding' AND entity_id=? ORDER BY created_at DESC`, id)
	defer rows.Close()
	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		rows.Scan(&l.ID, &l.Action, &l.Details, &l.CreatedAt)
		logs = append(logs, l)
	}
	if logs == nil {
		logs = []models.AuditLog{}
	}
	c.JSON(200, logs)
}

// ---- Jobs ----

func (h *Handler) GetJobs(c *gin.Context) {
	rows, _ := h.db.Query(`SELECT id, type, status, COALESCE(result,''), COALESCE(error,''), created_at, started_at, completed_at FROM jobs ORDER BY created_at DESC LIMIT 50`)
	defer rows.Close()
	var jobs []models.Job
	for rows.Next() {
		var j models.Job
		rows.Scan(&j.ID, &j.Type, &j.Status, &j.Result, &j.Error, &j.CreatedAt, &j.StartedAt, &j.CompletedAt)
		jobs = append(jobs, j)
	}
	if jobs == nil {
		jobs = []models.Job{}
	}
	c.JSON(200, jobs)
}

func (h *Handler) GetJob(c *gin.Context) {
	id := c.Param("id")
	var j models.Job
	err := h.db.QueryRow(`SELECT id, type, status, COALESCE(payload,''), COALESCE(result,''), COALESCE(error,''), created_at, started_at, completed_at FROM jobs WHERE id=?`, id).
		Scan(&j.ID, &j.Type, &j.Status, &j.Payload, &j.Result, &j.Error, &j.CreatedAt, &j.StartedAt, &j.CompletedAt)
	if err != nil {
		c.JSON(404, gin.H{"error": "Job not found"})
		return
	}
	c.JSON(200, j)
}

// ---- Stats ----

func (h *Handler) GetStats(c *gin.Context) {
	stats := map[string]interface{}{}

	var totalFindings, openFindings, confirmedFindings, closedFindings, fpFindings int
	h.db.QueryRow(`SELECT COUNT(*) FROM findings`).Scan(&totalFindings)
	h.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE status='open'`).Scan(&openFindings)
	h.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE status='confirmed'`).Scan(&confirmedFindings)
	h.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE status='closed'`).Scan(&closedFindings)
	h.db.QueryRow(`SELECT COUNT(*) FROM findings WHERE status='false_positive'`).Scan(&fpFindings)

	var totalScans, activeScans int
	h.db.QueryRow(`SELECT COUNT(*) FROM scans`).Scan(&totalScans)
	h.db.QueryRow(`SELECT COUNT(*) FROM scans WHERE status='running'`).Scan(&activeScans)

	var totalRepos int
	h.db.QueryRow(`SELECT COUNT(*) FROM repositories`).Scan(&totalRepos)

	var avgDaysExposed float64
	h.db.QueryRow(`SELECT COALESCE(AVG(days_exposed),0) FROM findings WHERE status='open'`).Scan(&avgDaysExposed)

	// Severity breakdown
	severityBreakdown := map[string]int{}
	rows, _ := h.db.Query(`SELECT severity, COUNT(*) FROM findings GROUP BY severity`)
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var sev string
			var count int
			rows.Scan(&sev, &count)
			severityBreakdown[sev] = count
		}
	}

	// Recent findings by type
	typeBreakdown := map[string]int{}
	rows2, _ := h.db.Query(`SELECT secret_type, COUNT(*) FROM findings GROUP BY secret_type ORDER BY COUNT(*) DESC LIMIT 10`)
	if rows2 != nil {
		defer rows2.Close()
		for rows2.Next() {
			var t string
			var count int
			rows2.Scan(&t, &count)
			typeBreakdown[t] = count
		}
	}

	stats["total_findings"] = totalFindings
	stats["open_findings"] = openFindings
	stats["confirmed_findings"] = confirmedFindings
	stats["closed_findings"] = closedFindings
	stats["false_positive_findings"] = fpFindings
	stats["total_scans"] = totalScans
	stats["active_scans"] = activeScans
	stats["total_repositories"] = totalRepos
	stats["avg_days_exposed"] = avgDaysExposed
	stats["severity_breakdown"] = severityBreakdown
	stats["type_breakdown"] = typeBreakdown

	c.JSON(200, stats)
}

// ---- Recipients ----

func (h *Handler) GetRecipients(c *gin.Context) {
	rows, _ := h.db.Query(`SELECT id, email, COALESCE(name,''), role, active, created_at FROM notification_recipients ORDER BY created_at DESC`)
	defer rows.Close()
	var recipients []models.NotificationRecipient
	for rows.Next() {
		var r models.NotificationRecipient
		rows.Scan(&r.ID, &r.Email, &r.Name, &r.Role, &r.Active, &r.CreatedAt)
		recipients = append(recipients, r)
	}
	if recipients == nil {
		recipients = []models.NotificationRecipient{}
	}
	c.JSON(200, recipients)
}

func (h *Handler) AddRecipient(c *gin.Context) {
	var req struct {
		Email string `json:"email" binding:"required"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if req.Role == "" {
		req.Role = "engineer"
	}
	res, err := h.db.Exec(`INSERT INTO notification_recipients (email, name, role) VALUES (?,?,?)`, req.Email, req.Name, req.Role)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	id, _ := res.LastInsertId()
	c.JSON(201, gin.H{"id": id})
}

func (h *Handler) DeleteRecipient(c *gin.Context) {
	id := c.Param("id")
	h.db.Exec(`DELETE FROM notification_recipients WHERE id=?`, id)
	c.JSON(200, gin.H{"message": "Deleted"})
}

// ---- Audit ----

func (h *Handler) GetAuditLogs(c *gin.Context) {
	rows, _ := h.db.Query(`SELECT id, action, COALESCE(entity_type,''), COALESCE(entity_id,0), COALESCE(details,''), created_at FROM audit_logs ORDER BY created_at DESC LIMIT 100`)
	defer rows.Close()
	var logs []models.AuditLog
	for rows.Next() {
		var l models.AuditLog
		rows.Scan(&l.ID, &l.Action, &l.EntityType, &l.EntityID, &l.Details, &l.CreatedAt)
		logs = append(logs, l)
	}
	if logs == nil {
		logs = []models.AuditLog{}
	}
	c.JSON(200, logs)
}

func (h *Handler) logAudit(action, entityType string, entityID int64, details string) {
	h.db.Exec(`INSERT INTO audit_logs (action, entity_type, entity_id, details) VALUES (?,?,?,?)`, action, entityType, entityID, details)
}

func mustParseInt(s string) int64 {
	n, _ := strconv.ParseInt(s, 10, 64)
	return n
}
