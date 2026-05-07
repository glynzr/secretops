package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

var allowedTypes = map[string]bool{
	"claude": true, "openai": true, "deepseek": true,
	"gemini": true, "ollama": true,
	"gitlab": true, "vault": true, "slack": true,
	"email": true, "aws": true, "github": true,
}

var sensitiveFields = map[string]bool{
	"token": true, "api_key": true, "api_key_2": true,
	"secret_access_key": true, "client_secret": true,
	"webhook_url": true, "password": true, "smtp_password": true,
}

func mask(v string) string {
	if len(v) <= 8 {
		return strings.Repeat("•", len(v))
	}
	return v[:4] + strings.Repeat("•", len(v)-8) + v[len(v)-4:]
}

func maskConfig(t string, cfg map[string]interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	for k, v := range cfg {
		if sensitiveFields[k] {
			if s, ok := v.(string); ok && s != "" {
				out[k] = mask(s)
				continue
			}
		}
		out[k] = v
	}
	return out
}

func (s *Server) getConnectionConfig(connType string) map[string]interface{} {
	var cfgStr string
	err := s.db.QueryRow(`SELECT config FROM connections WHERE org_id='default' AND type=?`, connType).Scan(&cfgStr)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	json.Unmarshal([]byte(cfgStr), &m)
	return m
}

func (s *Server) listConnections(c *gin.Context) {
	rows, err := s.db.Query(`SELECT id,type,config,status,error_msg,connected_at,created_at FROM connections ORDER BY created_at`)
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

func (s *Server) upsertConnection(c *gin.Context) {
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

	// Merge: keep existing sensitive values when new value is empty or masked (contains •)
	if existing := s.getConnectionConfig(t); existing != nil {
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
	_, err := s.db.Exec(`INSERT INTO connections(id,org_id,type,config,status) VALUES(?,'default',?,?,'disconnected')
		ON CONFLICT(org_id,type) DO UPDATE SET config=excluded.config`,
		id, t, string(cfgBytes))
	if err != nil {
		c.JSON(500, gin.H{"error": err.Error()})
		return
	}
	c.JSON(200, gin.H{"id": id, "status": "saved"})
}

func (s *Server) testConnection(c *gin.Context) {
	t := c.Param("type")
	cfg := s.getConnectionConfig(t)
	if cfg == nil {
		c.JSON(400, gin.H{"connected": false, "error": "not configured"})
		return
	}
	ok, errMsg := testConn(t, cfg)
	status := "disconnected"
	if ok {
		status = "connected"
	}
	connectedAt := ""
	if ok {
		connectedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.db.Exec(`UPDATE connections SET status=?,error_msg=?,connected_at=? WHERE org_id='default' AND type=?`,
		status, errMsg, connectedAt, t)
	c.JSON(200, gin.H{"connected": ok, "status": status, "error": errMsg})
}

func (s *Server) deleteConnection(c *gin.Context) {
	s.db.Exec(`DELETE FROM connections WHERE org_id='default' AND type=?`, c.Param("type"))
	c.JSON(200, gin.H{"deleted": true})
}

func (s *Server) getConnectionMasked(c *gin.Context) {
	cfg := s.getConnectionConfig(c.Param("type"))
	if cfg == nil {
		c.JSON(404, gin.H{"error": "not configured"})
		return
	}
	c.JSON(200, maskConfig(c.Param("type"), cfg))
}

func (s *Server) getConnectionRaw(c *gin.Context) {
	cfg := s.getConnectionConfig(c.Param("type"))
	if cfg == nil {
		c.JSON(404, gin.H{"error": "not configured"})
		return
	}
	c.JSON(200, cfg)
}

func testConn(t string, cfg map[string]interface{}) (bool, string) {
	str := func(k string) string {
		v, _ := cfg[k].(string)
		return v
	}
	switch t {
	case "claude", "openai", "gemini", "deepseek":
		k := str("api_key")
		if k == "" {
			return false, "API key not provided"
		}
		if len(k) < 10 {
			return false, "API key too short"
		}
		return true, ""
	case "ollama":
		url := str("base_url")
		if url == "" {
			return false, "Base URL not provided"
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Get(url + "/api/tags")
		if err != nil {
			return false, "Ollama unreachable: " + err.Error()
		}
		resp.Body.Close()
		return resp.StatusCode == 200, ""
	case "gitlab":
		rawURL, token := str("url"), str("token")
		if rawURL == "" || token == "" {
			return false, "URL and token required"
		}
		// Trim trailing slash so we never get double-slash API paths
		rawURL = strings.TrimRight(rawURL, "/")
		req, _ := http.NewRequest("GET", rawURL+"/api/v4/user", nil)
		req.Header.Set("PRIVATE-TOKEN", token)
		resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
		if err != nil {
			return false, "GitLab unreachable: " + err.Error()
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		switch resp.StatusCode {
		case 200:
			return true, ""
		case 401:
			return false, "Authentication failed — check your Personal Access Token"
		case 403:
			return false, "Access forbidden — token may lack required scopes (read_api, read_repository)"
		case 404:
			return false, "GitLab URL not found — verify the URL is correct"
		default:
			return false, fmt.Sprintf("GitLab returned HTTP %d", resp.StatusCode)
		}
	case "vault":
		addr, tok := str("addr"), str("token")
		if addr == "" {
			return false, "Vault address not provided"
		}
		req, _ := http.NewRequest("GET", addr+"/v1/sys/health", nil)
		if tok != "" {
			req.Header.Set("X-Vault-Token", tok)
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			return false, "Vault unreachable"
		}
		resp.Body.Close()
		return resp.StatusCode == 200, ""
	case "slack":
		wh := str("webhook_url")
		if wh == "" {
			return false, "Webhook URL not provided"
		}
		payload := `{"text":"✅ SecretOps connection test successful"}`
		resp, err := http.Post(wh, "application/json", strings.NewReader(payload))
		if err != nil {
			return false, err.Error()
		}
		resp.Body.Close()
		return resp.StatusCode == 200, ""
	case "email":
		if str("smtp_host") == "" || str("smtp_user") == "" {
			return false, "SMTP host and user required"
		}
		return true, "SMTP config saved — will validate on first send"
	case "aws":
		if str("access_key_id") == "" {
			return false, "Access key ID required"
		}
		return true, "AWS config saved"
	case "github":
		if str("token") == "" {
			return false, "Token required"
		}
		return true, "GitHub config saved"
	}
	return false, "unknown type"
}
