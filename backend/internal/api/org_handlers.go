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

// ── Helpers ───────────────────────────────────────────────────────────────────

func slugify(name string) string {
	s := strings.ToLower(name)
	var result []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			result = append(result, c)
		} else if (c == ' ' || c == '-' || c == '_') && len(result) > 0 && result[len(result)-1] != '-' {
			result = append(result, '-')
		}
	}
	for len(result) > 0 && result[len(result)-1] == '-' {
		result = result[:len(result)-1]
	}
	return string(result)
}

func (s *Server) getOrgConnectionConfig(orgID, connType string) map[string]interface{} {
	var cfgStr string
	err := s.db.QueryRow(`SELECT config FROM connections WHERE org_id=? AND type=?`, orgID, connType).Scan(&cfgStr)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	json.Unmarshal([]byte(cfgStr), &m)
	return m
}

// ── Organizations ─────────────────────────────────────────────────────────────

func (s *Server) listOrgs(c *gin.Context) {
	rows, err := s.db.Query(`SELECT id,name,slug,created_at FROM organizations ORDER BY created_at`)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var orgs []map[string]interface{}
	for rows.Next() {
		var id, name, slug, createdAt string
		rows.Scan(&id, &name, &slug, &createdAt)
		orgs = append(orgs, map[string]interface{}{
			"id": id, "name": name, "slug": slug, "created_at": createdAt,
		})
	}
	if orgs == nil {
		orgs = []map[string]interface{}{}
	}
	c.JSON(200, orgs)
}

func (s *Server) createOrg(c *gin.Context) {
	var body map[string]string
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	name := strings.TrimSpace(body["name"])
	if name == "" {
		c.JSON(400, gin.H{"error": "name is required"})
		return
	}
	id := uuid.New().String()
	slug := slugify(name)
	if slug == "" {
		slug = id[:8]
	}
	base := slug
	for i := 2; ; i++ {
		var count int
		s.db.QueryRow(`SELECT COUNT(*) FROM organizations WHERE slug=?`, slug).Scan(&count)
		if count == 0 {
			break
		}
		slug = fmt.Sprintf("%s-%d", base, i)
	}
	_, err := s.db.Exec(`INSERT INTO organizations(id,name,slug) VALUES(?,?,?)`, id, name, slug)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, gin.H{"id": id, "name": name, "slug": slug})
}

func (s *Server) getOrg(c *gin.Context) {
	id := c.Param("org_id")
	var name, slug, createdAt string
	err := s.db.QueryRow(`SELECT name,slug,created_at FROM organizations WHERE id=?`, id).Scan(&name, &slug, &createdAt)
	if err != nil {
		c.JSON(404, gin.H{"error": "org not found"})
		return
	}
	c.JSON(200, gin.H{"id": id, "name": name, "slug": slug, "created_at": createdAt})
}

func (s *Server) updateOrg(c *gin.Context) {
	id := c.Param("org_id")
	var body map[string]string
	c.ShouldBindJSON(&body)
	if name := strings.TrimSpace(body["name"]); name != "" {
		s.db.Exec(`UPDATE organizations SET name=? WHERE id=?`, name, id)
	}
	c.JSON(200, gin.H{"updated": true})
}

func (s *Server) deleteOrg(c *gin.Context) {
	id := c.Param("org_id")
	if id == "default" {
		c.JSON(400, gin.H{"error": "cannot delete the default organization"})
		return
	}
	s.db.Exec(`DELETE FROM connections WHERE org_id=?`, id)
	s.db.Exec(`DELETE FROM imported_projects WHERE org_id=?`, id)
	s.db.Exec(`DELETE FROM organizations WHERE id=?`, id)
	c.JSON(200, gin.H{"deleted": true})
}

// ── Org-scoped Connections ────────────────────────────────────────────────────

func (s *Server) listOrgConnections(c *gin.Context) {
	orgID := c.Param("org_id")
	rows, err := s.db.Query(`SELECT id,type,config,status,error_msg,connected_at,created_at FROM connections WHERE org_id=? ORDER BY created_at`, orgID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var conns []map[string]interface{}
	for rows.Next() {
		var id, typ, cfgStr, status, errMsg, createdAt string
		var connectedAt *string
		rows.Scan(&id, &typ, &cfgStr, &status, &errMsg, &connectedAt, &createdAt)
		var cfg map[string]interface{}
		json.Unmarshal([]byte(cfgStr), &cfg)
		conns = append(conns, map[string]interface{}{
			"id": id, "type": typ, "status": status,
			"error_msg": errMsg, "connected_at": connectedAt,
			"created_at": createdAt, "config": maskConfig(typ, cfg),
		})
	}
	if conns == nil {
		conns = []map[string]interface{}{}
	}
	c.JSON(200, conns)
}

func (s *Server) upsertOrgConnection(c *gin.Context) {
	orgID := c.Param("org_id")
	t := c.Param("type")
	if !allowedTypes[t] {
		c.JSON(400, gin.H{"error": "unknown connection type"})
		return
	}
	var cfg map[string]interface{}
	if err := c.ShouldBindJSON(&cfg); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	if existing := s.getOrgConnectionConfig(orgID, t); existing != nil {
		for k, existVal := range existing {
			if !sensitiveFields[k] {
				continue
			}
			newVal, _ := cfg[k].(string)
			if newVal == "" || strings.Contains(newVal, "•") {
				cfg[k] = existVal
			}
		}
	}
	cfgBytes, _ := json.Marshal(cfg)
	id := uuid.New().String()
	_, err := s.db.Exec(`INSERT INTO connections(id,org_id,type,config,status) VALUES(?,?,?,?,'disconnected')
		ON CONFLICT(org_id,type) DO UPDATE SET config=excluded.config`,
		id, orgID, t, string(cfgBytes))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"id": id, "status": "saved"})
}

func (s *Server) testOrgConnection(c *gin.Context) {
	orgID := c.Param("org_id")
	t := c.Param("type")
	cfg := s.getOrgConnectionConfig(orgID, t)
	if cfg == nil {
		c.JSON(400, gin.H{"connected": false, "error": "not configured"})
		return
	}
	ok, errMsg := testConn(t, cfg)
	status := "disconnected"
	connectedAt := ""
	if ok {
		status = "connected"
		connectedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.db.Exec(`UPDATE connections SET status=?,error_msg=?,connected_at=? WHERE org_id=? AND type=?`,
		status, errMsg, connectedAt, orgID, t)
	c.JSON(200, gin.H{"connected": ok, "status": status, "error": errMsg})
}

func (s *Server) deleteOrgConnection(c *gin.Context) {
	orgID := c.Param("org_id")
	s.db.Exec(`DELETE FROM connections WHERE org_id=? AND type=?`, orgID, c.Param("type"))
	c.JSON(200, gin.H{"deleted": true})
}

// ── Imported Projects ─────────────────────────────────────────────────────────

func (s *Server) listOrgProjects(c *gin.Context) {
	orgID := c.Param("org_id")
	rows, err := s.db.Query(`
		SELECT p.id, p.gitlab_id, p.name, p.path_with_namespace, p.http_url_to_repo,
		       p.default_branch, p.visibility, p.namespace_name, p.last_activity_at, p.imported_at,
		       COALESCE((SELECT COUNT(*) FROM scan_jobs WHERE repo_url=p.http_url_to_repo AND org_id=?), 0),
		       (SELECT status FROM scan_jobs WHERE repo_url=p.http_url_to_repo AND org_id=? ORDER BY created_at DESC LIMIT 1),
		       COALESCE((SELECT finding_count FROM scan_jobs WHERE repo_url=p.http_url_to_repo AND org_id=? ORDER BY created_at DESC LIMIT 1), 0),
		       (SELECT id FROM scan_jobs WHERE repo_url=p.http_url_to_repo AND org_id=? ORDER BY created_at DESC LIMIT 1)
		FROM imported_projects p WHERE p.org_id=? ORDER BY p.imported_at DESC`,
		orgID, orgID, orgID, orgID, orgID)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()
	var projects []map[string]interface{}
	for rows.Next() {
		var id, name, pathNS, httpURL, branch, vis, nsName, lastActivity, importedAt string
		var gitlabID, scanCount, lastFindingCount int
		var lastScanStatus, lastScanID *string
		rows.Scan(&id, &gitlabID, &name, &pathNS, &httpURL, &branch, &vis, &nsName,
			&lastActivity, &importedAt, &scanCount, &lastScanStatus, &lastFindingCount, &lastScanID)
		p := map[string]interface{}{
			"id": id, "org_id": orgID, "gitlab_id": gitlabID,
			"name": name, "path_with_namespace": pathNS,
			"http_url_to_repo": httpURL, "default_branch": branch,
			"visibility": vis, "namespace_name": nsName,
			"last_activity_at": lastActivity, "imported_at": importedAt,
			"scan_count": scanCount, "last_finding_count": lastFindingCount,
			"last_scan_status": nil, "last_scan_id": nil,
		}
		if lastScanStatus != nil {
			p["last_scan_status"] = *lastScanStatus
		}
		if lastScanID != nil {
			p["last_scan_id"] = *lastScanID
		}
		projects = append(projects, p)
	}
	if projects == nil {
		projects = []map[string]interface{}{}
	}
	c.JSON(200, projects)
}

func (s *Server) importOrgProject(c *gin.Context) {
	orgID := c.Param("org_id")
	var body map[string]interface{}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(400, gin.H{"error": err.Error()})
		return
	}
	str := func(k string) string { v, _ := body[k].(string); return v }
	num := func(k string) int { v, _ := body[k].(float64); return int(v) }
	id := uuid.New().String()
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO imported_projects(id,org_id,gitlab_id,name,path_with_namespace,http_url_to_repo,default_branch,visibility,namespace_name,last_activity_at)
		 VALUES(?,?,?,?,?,?,?,?,?,?)`,
		id, orgID, num("gitlab_id"), str("name"), str("path_with_namespace"),
		str("http_url_to_repo"), str("default_branch"), str("visibility"),
		str("namespace_name"), str("last_activity_at"))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(201, gin.H{"id": id, "org_id": orgID})
}

func (s *Server) removeOrgProject(c *gin.Context) {
	s.db.Exec(`DELETE FROM imported_projects WHERE id=? AND org_id=?`, c.Param("project_id"), c.Param("org_id"))
	c.JSON(200, gin.H{"deleted": true})
}

// ── Org-scoped GitLab Proxy ───────────────────────────────────────────────────

func (s *Server) listOrgGitLabRepos(c *gin.Context) {
	orgID := c.Param("org_id")
	cfg := s.getOrgConnectionConfig(orgID, "gitlab")
	if cfg == nil {
		c.JSON(400, gin.H{"error": "GitLab not configured for this organization"})
		return
	}
	gitlabURL := strings.TrimRight(cfg["url"].(string), "/")
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

func (s *Server) listOrgGitLabGroups(c *gin.Context) {
	orgID := c.Param("org_id")
	cfg := s.getOrgConnectionConfig(orgID, "gitlab")
	if cfg == nil {
		c.JSON(400, gin.H{"error": "GitLab not configured for this organization"})
		return
	}
	gitlabURL := strings.TrimRight(cfg["url"].(string), "/")
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

// ── Org-scoped Scans ──────────────────────────────────────────────────────────

func (s *Server) listOrgScans(c *gin.Context) {
	orgID := c.Param("org_id")
	rows, _ := s.db.Query(`SELECT id,repo_url,repo_name,branch,status,ai_model,total_files,scanned_files,finding_count,error_msg,created_at,updated_at FROM scan_jobs WHERE org_id=? ORDER BY created_at DESC LIMIT 100`, orgID)
	defer rows.Close()
	var scans []map[string]interface{}
	for rows.Next() {
		var id, repoURL, repoName, branch, status, aiModel, errMsg, createdAt, updatedAt string
		var totalFiles, scannedFiles, findingCount int
		rows.Scan(&id, &repoURL, &repoName, &branch, &status, &aiModel, &totalFiles, &scannedFiles, &findingCount, &errMsg, &createdAt, &updatedAt)
		scans = append(scans, map[string]interface{}{
			"id": id, "repo_url": repoURL, "repo_name": repoName, "branch": branch,
			"status": status, "ai_model": aiModel, "total_files": totalFiles,
			"scanned_files": scannedFiles, "finding_count": findingCount,
			"error_msg": errMsg, "created_at": createdAt, "updated_at": updatedAt,
		})
	}
	if scans == nil {
		scans = []map[string]interface{}{}
	}
	c.JSON(200, scans)
}

func (s *Server) createOrgScan(c *gin.Context) {
	orgID := c.Param("org_id")
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
	for i := len(repoName) - 1; i >= 0; i-- {
		if repoName[i] == '/' {
			repoName = repoName[i+1:]
			break
		}
	}
	repoName = strings.TrimSuffix(repoName, ".git")

	_, err := s.db.Exec(`INSERT INTO scan_jobs(id,org_id,repo_url,repo_name,branch,ai_model,status) VALUES(?,?,?,?,?,?,'pending')`,
		id, orgID, repoURL, repoName, branch, aiModel)
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}

	// Build CLI payload with org credentials
	claudeCfg := s.getOrgConnectionConfig(orgID, "claude")
	gitlabCfg := s.getOrgConnectionConfig(orgID, "gitlab")
	cliPayload := map[string]interface{}{
		"scan_id": id, "repo_url": repoURL, "branch": branch, "ai_model": aiModel,
	}
	if claudeCfg != nil {
		cliPayload["claude_api_key"], _ = claudeCfg["api_key"].(string)
		if k2, ok := claudeCfg["api_key_2"].(string); ok && k2 != "" {
			cliPayload["claude_api_key_2"] = k2
		}
	}
	if gitlabCfg != nil {
		cliPayload["gitlab_token"], _ = gitlabCfg["token"].(string)
		cliPayload["gitlab_url"], _ = gitlabCfg["url"].(string)
	}

	go func() {
		payload, _ := json.Marshal(cliPayload)
		http.Post("http://cli-service:5001/scan", "application/json", bytes.NewReader(payload))
	}()

	c.JSON(201, gin.H{"id": id, "status": "pending"})
}

// ── Org-scoped Findings ───────────────────────────────────────────────────────

func (s *Server) listOrgFindings(c *gin.Context) {
	orgID := c.Param("org_id")
	status := c.Query("status")
	severity := c.Query("severity")

	query := `SELECT f.id,f.scan_id,f.file_path,f.line_number,f.candidate_value,f.context_code,
		f.is_secret,f.confidence,f.secret_type,f.severity,f.reasoning,f.status,f.ai_model,
		f.env_var_suggestion,f.vault_path_suggestion,f.commit_author,f.commit_email,
		f.days_in_history,f.history_alert_level,f.first_seen_date,f.remediation_id,f.created_at
		FROM findings f JOIN scan_jobs s ON f.scan_id=s.id WHERE s.org_id=?`
	args := []interface{}{orgID}
	if status != "" {
		query += " AND f.status=?"
		args = append(args, status)
	}
	if severity != "" {
		query += " AND f.severity=?"
		args = append(args, severity)
	}
	query += " ORDER BY CASE f.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, f.confidence DESC LIMIT 500"
	rows, _ := s.db.Query(query, args...)
	defer rows.Close()
	c.JSON(200, scanFindings(rows))
}

// ── Org-scoped Remediations ───────────────────────────────────────────────────

func (s *Server) listOrgRemediations(c *gin.Context) {
	orgID := c.Param("org_id")
	rows, _ := s.db.Query(`
		SELECT r.id,r.finding_id,r.scan_id,r.repo_url,r.status,r.vault_path,r.vault_status,
		       r.mr_url,r.mr_number,r.mr_branch,r.patch_content,r.env_var_name,
		       r.issue_url,r.issue_number,r.slack_status,r.email_status,
		       r.revocation_status,r.revocation_msg,r.post_merge_status,r.error_msg,
		       r.created_at,r.updated_at
		FROM remediation_jobs r JOIN scan_jobs s ON r.scan_id=s.id
		WHERE s.org_id=? ORDER BY r.created_at DESC LIMIT 100`, orgID)
	defer rows.Close()
	c.JSON(200, scanRemediations(rows))
}

// ── Org-scoped History Alerts ─────────────────────────────────────────────────

func (s *Server) listOrgHistoryAlerts(c *gin.Context) {
	orgID := c.Param("org_id")
	rows, _ := s.db.Query(`
		SELECT h.id,h.finding_id,h.scan_id,h.repo_name,h.days_exposed,h.alert_level,
		       h.first_seen_commit,h.first_seen_author,h.first_seen_date,
		       h.commit_count,h.slack_sent,h.email_sent,h.created_at
		FROM history_alerts h JOIN scan_jobs s ON h.scan_id=s.id
		WHERE s.org_id=? ORDER BY h.days_exposed DESC LIMIT 100`, orgID)
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

// ── Org Stats ─────────────────────────────────────────────────────────────────

func (s *Server) getOrgStats(c *gin.Context) {
	orgID := c.Param("org_id")
	var totalFindings, openFindings, critical, high int
	s.db.QueryRow(`SELECT COUNT(*) FROM findings f JOIN scan_jobs s ON f.scan_id=s.id WHERE s.org_id=? AND f.is_secret=1`, orgID).Scan(&totalFindings)
	s.db.QueryRow(`SELECT COUNT(*) FROM findings f JOIN scan_jobs s ON f.scan_id=s.id WHERE s.org_id=? AND f.is_secret=1 AND f.status='open'`, orgID).Scan(&openFindings)
	s.db.QueryRow(`SELECT COUNT(*) FROM findings f JOIN scan_jobs s ON f.scan_id=s.id WHERE s.org_id=? AND f.is_secret=1 AND f.severity='critical'`, orgID).Scan(&critical)
	s.db.QueryRow(`SELECT COUNT(*) FROM findings f JOIN scan_jobs s ON f.scan_id=s.id WHERE s.org_id=? AND f.is_secret=1 AND f.severity='high'`, orgID).Scan(&high)
	var projectCount, scanCount int
	s.db.QueryRow(`SELECT COUNT(*) FROM imported_projects WHERE org_id=?`, orgID).Scan(&projectCount)
	s.db.QueryRow(`SELECT COUNT(*) FROM scan_jobs WHERE org_id=?`, orgID).Scan(&scanCount)
	c.JSON(200, gin.H{
		"total_findings": totalFindings, "open_findings": openFindings,
		"critical": critical, "high": high,
		"project_count": projectCount, "scan_count": scanCount,
	})
}
