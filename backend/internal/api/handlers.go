package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ── Scans ─────────────────────────────────────────────────────────────────────

func (s *Server) createScan(c *gin.Context) {
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	id := uuid.New().String()
	repoURL, _ := body["repo_url"].(string)
	branch, _ := body["branch"].(string)
	if branch == "" {
		branch = "main"
	}
	aiModel, _ := body["ai_model"].(string)
	if aiModel == "" {
		aiModel = "claude-3-5-sonnet-20241022"
	}
	repoName := repoURL
	for _, sep := range []string{"/", ".git"} {
		if idx := len(repoName) - len(sep); idx > 0 && repoName[idx:] == sep {
			repoName = repoName[:idx]
		}
	}
	if lastSlash := len(repoName) - 1; lastSlash > 0 {
		for i := len(repoName) - 1; i >= 0; i-- {
			if repoName[i] == '/' {
				repoName = repoName[i+1:]
				break
			}
		}
	}

	_, err := s.db.Exec(`INSERT INTO scan_jobs(id,repo_url,repo_name,branch,ai_model,status) VALUES(?,?,?,?,?,'pending')`,
		id, repoURL, repoName, branch, aiModel)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Dispatch to CLI service
	go func() {
		cliPayload, _ := json.Marshal(map[string]interface{}{
			"scan_id": id, "repo_url": repoURL, "branch": branch, "ai_model": aiModel,
		})
		http.Post("http://cli-service:5001/scan", "application/json", bytes.NewReader(cliPayload))
	}()

	c.JSON(201, gin.H{"id": id, "status": "pending"})
}

func (s *Server) listScans(c *gin.Context) {
	rows, _ := s.db.Query(`SELECT id,repo_url,repo_name,branch,status,ai_model,total_files,scanned_files,finding_count,error_msg,created_at,updated_at FROM scan_jobs ORDER BY created_at DESC LIMIT 50`)
	defer rows.Close()
	var scans []map[string]interface{}
	for rows.Next() {
		var m map[string]interface{}
		var id, repoURL, repoName, branch, status, aiModel, errMsg, createdAt, updatedAt string
		var totalFiles, scannedFiles, findingCount int
		rows.Scan(&id, &repoURL, &repoName, &branch, &status, &aiModel, &totalFiles, &scannedFiles, &findingCount, &errMsg, &createdAt, &updatedAt)
		m = map[string]interface{}{"id": id, "repo_url": repoURL, "repo_name": repoName, "branch": branch, "status": status, "ai_model": aiModel, "total_files": totalFiles, "scanned_files": scannedFiles, "finding_count": findingCount, "error_msg": errMsg, "created_at": createdAt, "updated_at": updatedAt}
		scans = append(scans, m)
	}
	if scans == nil {
		scans = []map[string]interface{}{}
	}
	c.JSON(200, scans)
}

func (s *Server) getScan(c *gin.Context) {
	id := c.Param("id")
	var repoURL, repoName, branch, status, aiModel, errMsg, createdAt, updatedAt string
	var totalFiles, scannedFiles, findingCount int
	err := s.db.QueryRow(`SELECT repo_url,repo_name,branch,status,ai_model,total_files,scanned_files,finding_count,error_msg,created_at,updated_at FROM scan_jobs WHERE id=?`, id).
		Scan(&repoURL, &repoName, &branch, &status, &aiModel, &totalFiles, &scannedFiles, &findingCount, &errMsg, &createdAt, &updatedAt)
	if err != nil {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	c.JSON(200, gin.H{"id": id, "repo_url": repoURL, "repo_name": repoName, "branch": branch, "status": status, "ai_model": aiModel, "total_files": totalFiles, "scanned_files": scannedFiles, "finding_count": findingCount, "error_msg": errMsg, "created_at": createdAt, "updated_at": updatedAt})
}

func (s *Server) updateScan(c *gin.Context) {
	var body map[string]interface{}
	c.ShouldBindJSON(&body)
	status, _ := body["status"].(string)
	totalFiles, _ := body["total_files"].(float64)
	scannedFiles, _ := body["scanned_files"].(float64)
	findingCount, _ := body["finding_count"].(float64)
	errMsg, _ := body["error_msg"].(string)
	s.db.Exec(`UPDATE scan_jobs SET status=?,total_files=?,scanned_files=?,finding_count=?,error_msg=?,updated_at=datetime('now') WHERE id=?`,
		status, int(totalFiles), int(scannedFiles), int(findingCount), errMsg, c.Param("id"))
	c.JSON(200, gin.H{"updated": true})
}

func (s *Server) deleteScan(c *gin.Context) {
	s.db.Exec(`DELETE FROM scan_jobs WHERE id=?`, c.Param("id"))
	s.db.Exec(`DELETE FROM findings WHERE scan_id=?`, c.Param("id"))
	c.JSON(200, gin.H{"deleted": true})
}

func (s *Server) getScanFindings(c *gin.Context) {
	rows, _ := s.db.Query(`SELECT id,file_path,line_number,candidate_value,context_code,is_secret,confidence,secret_type,severity,reasoning,status,ai_model,env_var_suggestion,vault_path_suggestion,commit_author,commit_email,days_in_history,history_alert_level,first_seen_date,remediation_id,created_at FROM findings WHERE scan_id=? ORDER BY severity,confidence DESC`, c.Param("id"))
	defer rows.Close()
	c.JSON(200, scanFindings(rows))
}

// ── Findings ─────────────────────────────────────────────────────────────────

func (s *Server) createFinding(c *gin.Context) {
	var body map[string]interface{}
	c.ShouldBindJSON(&body)
	id, _ := body["id"].(string)
	if id == "" {
		id = uuid.New().String()
	}
	str := func(k string) string { v, _ := body[k].(string); return v }
	num := func(k string) float64 { v, _ := body[k].(float64); return v }
	boolV := func(k string) int {
		if v, ok := body[k].(bool); ok && v {
			return 1
		}
		return 0
	}
	s.db.Exec(`INSERT OR IGNORE INTO findings(id,scan_id,file_path,line_number,candidate_value,context_code,is_secret,confidence,secret_type,severity,reasoning,status,ai_model,env_var_suggestion,vault_path_suggestion,commit_author,commit_email,days_in_history,history_alert_level,first_seen_date,remediation_id) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, str("scan_id"), str("file_path"), int(num("line_number")),
		str("candidate_value"), str("context_code"), boolV("is_secret"),
		num("confidence"), str("secret_type"), str("severity"), str("reasoning"),
		str("status"), str("ai_model"), str("env_var_suggestion"),
		str("vault_path_suggestion"), str("commit_author"), str("commit_email"),
		int(num("days_in_history")), str("history_alert_level"),
		str("first_seen_date"), str("remediation_id"))
	c.JSON(201, gin.H{"id": id})
}

func (s *Server) listFindings(c *gin.Context) {
	status := c.Query("status")
	severity := c.Query("severity")
	query := `SELECT id,scan_id,file_path,line_number,candidate_value,context_code,is_secret,confidence,secret_type,severity,reasoning,status,ai_model,env_var_suggestion,vault_path_suggestion,commit_author,commit_email,days_in_history,history_alert_level,first_seen_date,remediation_id,created_at FROM findings WHERE 1=1`
	args := []interface{}{}
	if status != "" {
		query += " AND status=?"
		args = append(args, status)
	}
	if severity != "" {
		query += " AND severity=?"
		args = append(args, severity)
	}
	query += " ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, confidence DESC LIMIT 200"
	rows, _ := s.db.Query(query, args...)
	defer rows.Close()
	c.JSON(200, scanFindings(rows))
}

func (s *Server) getFinding(c *gin.Context) {
	rows, _ := s.db.Query(`SELECT id,scan_id,file_path,line_number,candidate_value,context_code,is_secret,confidence,secret_type,severity,reasoning,status,ai_model,env_var_suggestion,vault_path_suggestion,commit_author,commit_email,days_in_history,history_alert_level,first_seen_date,remediation_id,created_at FROM findings WHERE id=?`, c.Param("id"))
	defer rows.Close()
	findings := scanFindings(rows)
	if len(findings) == 0 {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	c.JSON(200, findings[0])
}

func (s *Server) updateFindingStatus(c *gin.Context) {
	var body map[string]string
	c.ShouldBindJSON(&body)
	s.db.Exec(`UPDATE findings SET status=? WHERE id=?`, body["status"], c.Param("id"))
	c.JSON(200, gin.H{"updated": true})
}

func (s *Server) triggerRemediation(c *gin.Context) {
	findingID := c.Param("id")
	// Get finding details
	rows, _ := s.db.Query(`SELECT id,scan_id,file_path,line_number,candidate_value,context_code,secret_type,severity,ai_model,env_var_suggestion,vault_path_suggestion,commit_author,commit_email,days_in_history,history_alert_level FROM findings WHERE id=?`, findingID)
	defer rows.Close()
	if !rows.Next() {
		c.JSON(404, gin.H{"error": "finding not found"})
		return
	}
	var fID, scanID, filePath, candidateValue, contextCode, secretType, severity, aiModel, envVar, vaultPath, author, email, histLevel string
	var lineNumber, daysInHistory int
	rows.Scan(&fID, &scanID, &filePath, &lineNumber, &candidateValue, &contextCode, &secretType, &severity, &aiModel, &envVar, &vaultPath, &author, &email, &daysInHistory, &histLevel)

	// Get repo_url from scan
	var repoURL string
	s.db.QueryRow(`SELECT repo_url FROM scan_jobs WHERE id=?`, scanID).Scan(&repoURL)

	remID := uuid.New().String()
	s.db.Exec(`INSERT INTO remediation_jobs(id,finding_id,scan_id,repo_url,status) VALUES(?,?,?,?,'pending')`,
		remID, findingID, scanID, repoURL)
	s.db.Exec(`UPDATE findings SET remediation_id=? WHERE id=?`, remID, findingID)

	go func() {
		payload, _ := json.Marshal(map[string]interface{}{
			"remediation_id": remID, "finding_id": fID, "scan_id": scanID,
			"file_path": filePath, "line_number": lineNumber,
			"candidate_value": candidateValue, "context_code": contextCode,
			"secret_type": secretType, "severity": severity, "ai_model": aiModel,
			"env_var_suggestion": envVar, "vault_path_suggestion": vaultPath,
			"commit_author": author, "commit_email": email,
			"repo_url": repoURL, "days_in_history": daysInHistory,
			"history_alert_level": histLevel,
		})
		http.Post("http://cli-service:5001/remediate", "application/json", bytes.NewReader(payload))
	}()

	c.JSON(200, gin.H{"remediation_id": remID})
}

// ── Remediations ──────────────────────────────────────────────────────────────

func (s *Server) listRemediations(c *gin.Context) {
	rows, _ := s.db.Query(`SELECT id,finding_id,scan_id,repo_url,status,vault_path,vault_status,mr_url,mr_number,mr_branch,patch_content,env_var_name,issue_url,issue_number,slack_status,email_status,revocation_status,revocation_msg,post_merge_status,error_msg,created_at,updated_at FROM remediation_jobs ORDER BY created_at DESC LIMIT 50`)
	defer rows.Close()
	c.JSON(200, scanRemediations(rows))
}

func (s *Server) getRemediation(c *gin.Context) {
	rows, _ := s.db.Query(`SELECT id,finding_id,scan_id,repo_url,status,vault_path,vault_status,mr_url,mr_number,mr_branch,patch_content,env_var_name,issue_url,issue_number,slack_status,email_status,revocation_status,revocation_msg,post_merge_status,error_msg,created_at,updated_at FROM remediation_jobs WHERE id=?`, c.Param("id"))
	defer rows.Close()
	rems := scanRemediations(rows)
	if len(rems) == 0 {
		c.JSON(404, gin.H{"error": "not found"})
		return
	}
	c.JSON(200, rems[0])
}

func (s *Server) updateRemediation(c *gin.Context) {
	var body map[string]interface{}
	c.ShouldBindJSON(&body)
	str := func(k string) string { v, _ := body[k].(string); return v }
	num := func(k string) int { v, _ := body[k].(float64); return int(v) }
	s.db.Exec(`UPDATE remediation_jobs SET status=?,vault_path=?,vault_status=?,mr_url=?,mr_number=?,mr_branch=?,patch_content=?,env_var_name=?,issue_url=?,issue_number=?,slack_status=?,email_status=?,revocation_status=?,revocation_msg=?,error_msg=?,updated_at=datetime('now') WHERE id=?`,
		str("status"), str("vault_path"), str("vault_status"),
		str("mr_url"), num("mr_number"), str("mr_branch"),
		str("patch_content"), str("env_var_name"),
		str("issue_url"), num("issue_number"),
		str("slack_status"), str("email_status"),
		str("revocation_status"), str("revocation_msg"),
		str("error_msg"), c.Param("id"))
	c.JSON(200, gin.H{"updated": true})
}

func (s *Server) postMergeVerify(c *gin.Context) {
	// Trigger post-merge verification in CLI service
	remID := c.Param("id")
	var findingID, repoURL, vaultPath string
	s.db.QueryRow(`SELECT finding_id,repo_url,vault_path FROM remediation_jobs WHERE id=?`, remID).
		Scan(&findingID, &repoURL, &vaultPath)

	payload, _ := json.Marshal(map[string]interface{}{
		"remediation_id": remID, "finding_id": findingID,
		"repo_url": repoURL, "vault_path": vaultPath,
	})
	go http.Post("http://cli-service:5001/verify", "application/json", bytes.NewReader(payload))
	c.JSON(200, gin.H{"status": "verification_queued"})
}

// ── History Alerts ────────────────────────────────────────────────────────────

func (s *Server) listHistoryAlerts(c *gin.Context) {
	rows, _ := s.db.Query(`SELECT id,finding_id,scan_id,repo_name,days_exposed,alert_level,first_seen_commit,first_seen_author,first_seen_date,commit_count,slack_sent,email_sent,created_at FROM history_alerts ORDER BY days_exposed DESC LIMIT 50`)
	defer rows.Close()
	var alerts []map[string]interface{}
	for rows.Next() {
		var id, findingID, scanID, repoName, alertLevel, firstCommit, firstAuthor, firstDate, createdAt string
		var daysExposed, commitCount, slackSent, emailSent int
		rows.Scan(&id, &findingID, &scanID, &repoName, &daysExposed, &alertLevel, &firstCommit, &firstAuthor, &firstDate, &commitCount, &slackSent, &emailSent, &createdAt)
		alerts = append(alerts, map[string]interface{}{
			"id": id, "finding_id": findingID, "scan_id": scanID, "repo_name": repoName,
			"days_exposed": daysExposed, "alert_level": alertLevel,
			"first_seen_commit": firstCommit, "first_seen_author": firstAuthor,
			"first_seen_date": firstDate, "commit_count": commitCount,
			"slack_sent": slackSent == 1, "email_sent": emailSent == 1, "created_at": createdAt,
		})
	}
	if alerts == nil {
		alerts = []map[string]interface{}{}
	}
	c.JSON(200, alerts)
}

func (s *Server) createHistoryAlert(c *gin.Context) {
	var body map[string]interface{}
	c.ShouldBindJSON(&body)
	id := uuid.New().String()
	str := func(k string) string { v, _ := body[k].(string); return v }
	num := func(k string) int { v, _ := body[k].(float64); return int(v) }
	s.db.Exec(`INSERT OR IGNORE INTO history_alerts(id,finding_id,scan_id,repo_name,days_exposed,alert_level,first_seen_commit,first_seen_author,first_seen_date,commit_count,slack_sent,email_sent) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		id, str("finding_id"), str("scan_id"), str("repo_name"),
		num("days_exposed"), str("alert_level"), str("first_seen_commit"),
		str("first_seen_author"), str("first_seen_date"), num("commit_count"),
		num("slack_sent"), num("email_sent"))
	c.JSON(201, gin.H{"id": id})
}

// ── GitLab Proxy ──────────────────────────────────────────────────────────────

func (s *Server) listGitLabRepos(c *gin.Context) {
	cfg := s.getConnectionConfig("gitlab")
	if cfg == nil {
		c.JSON(400, gin.H{"error": "GitLab not configured"})
		return
	}
	gitlabURL, _ := cfg["url"].(string)
	gitlabURL = strings.TrimRight(gitlabURL, "/")
	token, _ := cfg["token"].(string)
	search := c.Query("search")
	page := c.DefaultQuery("page", "1")
	groupID := c.Query("group_id")

	var apiURL string
	if groupID != "" {
		apiURL = fmt.Sprintf("%s/api/v4/groups/%s/projects?page=%s&per_page=50&order_by=last_activity_at&sort=desc&include_subgroups=true", gitlabURL, groupID, page)
	} else {
		apiURL = fmt.Sprintf("%s/api/v4/projects?page=%s&per_page=50&membership=true&order_by=last_activity_at&sort=desc", gitlabURL, page)
	}
	if search != "" {
		apiURL += "&search=" + search
	}

	req, _ := http.NewRequest("GET", apiURL, nil)
	req.Header.Set("PRIVATE-TOKEN", token)
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var repos interface{}
	json.Unmarshal(body, &repos)
	c.JSON(200, gin.H{
		"repos":       repos,
		"page":        page,
		"total_pages": resp.Header.Get("X-Total-Pages"),
		"total":       resp.Header.Get("X-Total"),
	})
}

func (s *Server) listGitLabGroups(c *gin.Context) {
	cfg := s.getConnectionConfig("gitlab")
	if cfg == nil {
		c.JSON(400, gin.H{"error": "GitLab not configured"})
		return
	}
	gitlabURL, _ := cfg["url"].(string)
	gitlabURL = strings.TrimRight(gitlabURL, "/")
	token, _ := cfg["token"].(string)
	req, _ := http.NewRequest("GET", gitlabURL+"/api/v4/groups?min_access_level=10&per_page=100", nil)
	req.Header.Set("PRIVATE-TOKEN", token)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var groups interface{}
	json.Unmarshal(body, &groups)
	c.JSON(200, gin.H{"groups": groups})
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func scanFindings(rows interface{ Next() bool; Scan(...interface{}) error }) []map[string]interface{} {
	var findings []map[string]interface{}
	for rows.Next() {
		var id, scanID, filePath, candidateValue, contextCode, secretType, severity, reasoning, status, aiModel, envVar, vaultPath, author, email, histLevel, firstDate, remID, createdAt string
		var lineNumber, daysInHistory int
		var isSecret int
		var confidence float64
		rows.Scan(&id, &scanID, &filePath, &lineNumber, &candidateValue, &contextCode, &isSecret, &confidence, &secretType, &severity, &reasoning, &status, &aiModel, &envVar, &vaultPath, &author, &email, &daysInHistory, &histLevel, &firstDate, &remID, &createdAt)
		findings = append(findings, map[string]interface{}{
			"id": id, "scan_id": scanID, "file_path": filePath, "line_number": lineNumber,
			"candidate_value": candidateValue, "context_code": contextCode,
			"is_secret": isSecret == 1, "confidence": confidence,
			"secret_type": secretType, "severity": severity, "reasoning": reasoning,
			"status": status, "ai_model": aiModel, "env_var_suggestion": envVar,
			"vault_path_suggestion": vaultPath, "commit_author": author, "commit_email": email,
			"days_in_history": daysInHistory, "history_alert_level": histLevel,
			"first_seen_date": firstDate, "remediation_id": remID, "created_at": createdAt,
		})
	}
	if findings == nil {
		findings = []map[string]interface{}{}
	}
	return findings
}

func scanRemediations(rows interface{ Next() bool; Scan(...interface{}) error }) []map[string]interface{} {
	var rems []map[string]interface{}
	for rows.Next() {
		var id, findingID, scanID, repoURL, status, vaultPath, vaultStatus, mrURL, mrBranch, patchContent, envVarName, issueURL, slackStatus, emailStatus, revStatus, revMsg, postMergeStatus, errMsg, createdAt, updatedAt string
		var mrNumber, issueNumber int
		rows.Scan(&id, &findingID, &scanID, &repoURL, &status, &vaultPath, &vaultStatus, &mrURL, &mrNumber, &mrBranch, &patchContent, &envVarName, &issueURL, &issueNumber, &slackStatus, &emailStatus, &revStatus, &revMsg, &postMergeStatus, &errMsg, &createdAt, &updatedAt)
		rems = append(rems, map[string]interface{}{
			"id": id, "finding_id": findingID, "scan_id": scanID, "repo_url": repoURL,
			"status": status, "vault_path": vaultPath, "vault_status": vaultStatus,
			"mr_url": mrURL, "mr_number": mrNumber, "mr_branch": mrBranch,
			"patch_content": patchContent, "env_var_name": envVarName,
			"issue_url": issueURL, "issue_number": issueNumber,
			"slack_status": slackStatus, "email_status": emailStatus,
			"revocation_status": revStatus, "revocation_msg": revMsg,
			"post_merge_status": postMergeStatus, "error_msg": errMsg,
			"created_at": createdAt, "updated_at": updatedAt,
		})
	}
	if rems == nil {
		rems = []map[string]interface{}{}
	}
	return rems
}
