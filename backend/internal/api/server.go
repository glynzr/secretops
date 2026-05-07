package api

import (
	"net/http"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/secretops/backend/internal/models"
)

type Server struct {
	db     *models.DB
	port   string
	router *gin.Engine
}

func NewServer(db *models.DB, port string) *Server {
	s := &Server{db: db, port: port}
	s.setup()
	return s
}

func (s *Server) setup() {
	r := gin.Default()
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{"*"},
		AllowMethods: []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Authorization"},
	}))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "version": "3.0.0"})
	})

	v1 := r.Group("/api/v1")

	// ── Organizations ─────────────────────────────────────────────────────────
	v1.GET("/orgs", s.listOrgs)
	v1.POST("/orgs", s.createOrg)
	v1.GET("/orgs/:org_id", s.getOrg)
	v1.PUT("/orgs/:org_id", s.updateOrg)
	v1.DELETE("/orgs/:org_id", s.deleteOrg)

	// Org-scoped stats
	v1.GET("/orgs/:org_id/stats", s.getOrgStats)

	// Org-scoped connections
	v1.GET("/orgs/:org_id/connections", s.listOrgConnections)
	v1.PUT("/orgs/:org_id/connections/:type", s.upsertOrgConnection)
	v1.POST("/orgs/:org_id/connections/:type/test", s.testOrgConnection)
	v1.DELETE("/orgs/:org_id/connections/:type", s.deleteOrgConnection)

	// Org-scoped imported projects
	v1.GET("/orgs/:org_id/projects", s.listOrgProjects)
	v1.POST("/orgs/:org_id/projects", s.importOrgProject)
	v1.DELETE("/orgs/:org_id/projects/:project_id", s.removeOrgProject)

	// Org-scoped GitLab proxy
	v1.GET("/orgs/:org_id/gitlab/repos", s.listOrgGitLabRepos)
	v1.GET("/orgs/:org_id/gitlab/groups", s.listOrgGitLabGroups)

	// Org-scoped scans
	v1.GET("/orgs/:org_id/scans", s.listOrgScans)
	v1.POST("/orgs/:org_id/scans", s.createOrgScan)

	// Org-scoped findings
	v1.GET("/orgs/:org_id/findings", s.listOrgFindings)

	// Org-scoped remediations
	v1.GET("/orgs/:org_id/remediations", s.listOrgRemediations)

	// Org-scoped history alerts
	v1.GET("/orgs/:org_id/history-alerts", s.listOrgHistoryAlerts)

	// ── Legacy routes (used by CLI service callbacks) ─────────────────────────
	v1.GET("/connections", s.listConnections)
	v1.PUT("/connections/:type", s.upsertConnection)
	v1.POST("/connections/:type/test", s.testConnection)
	v1.DELETE("/connections/:type", s.deleteConnection)
	v1.GET("/connections/:type/config", s.getConnectionMasked)
	v1.GET("/connections/:type/config/raw", s.getConnectionRaw)

	v1.GET("/gitlab/repos", s.listGitLabRepos)
	v1.GET("/gitlab/groups", s.listGitLabGroups)

	v1.POST("/scans", s.createScan)
	v1.GET("/scans", s.listScans)
	v1.GET("/scans/:id", s.getScan)
	v1.PATCH("/scans/:id", s.updateScan)
	v1.DELETE("/scans/:id", s.deleteScan)
	v1.GET("/scans/:id/findings", s.getScanFindings)

	v1.POST("/findings", s.createFinding)
	v1.GET("/findings", s.listFindings)
	v1.GET("/findings/:id", s.getFinding)
	v1.PATCH("/findings/:id/status", s.updateFindingStatus)
	v1.POST("/findings/:id/remediate", s.triggerRemediation)

	v1.GET("/remediations", s.listRemediations)
	v1.GET("/remediations/:id", s.getRemediation)
	v1.PATCH("/remediations/:id", s.updateRemediation)
	v1.POST("/remediations/:id/verify", s.postMergeVerify)

	v1.GET("/history-alerts", s.listHistoryAlerts)
	v1.POST("/history-alerts", s.createHistoryAlert)

	s.router = r
}

func (s *Server) Run() error {
	return s.router.Run(":" + s.port)
}
