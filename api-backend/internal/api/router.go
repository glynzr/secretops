package api

import (
	"database/sql"
	"net/http"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

func SetupRouter(db *sql.DB) *gin.Engine {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:3000", "http://frontend:3000"},
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	h := NewHandler(db)

	v1 := r.Group("/api/v1")
	{
		// Health
		v1.GET("/health", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "secretops-api"})
		})

		// Integrations
		v1.GET("/integrations", h.GetIntegrations)
		v1.POST("/integrations", h.SaveIntegration)
		v1.POST("/integrations/:type/test", h.TestIntegration)
		v1.DELETE("/integrations/:type", h.DeleteIntegration)

		// Repositories
		v1.GET("/repositories", h.GetRepositories)
		v1.GET("/repositories/gitlab", h.ListGitLabRepositories)
		v1.POST("/repositories", h.AddRepository)

		// Scans
		v1.POST("/scans", h.StartScan)
		v1.GET("/scans/:id", h.GetScan)
		v1.GET("/scans/:id/stream", h.StreamScanStatus)

		// Findings
		v1.GET("/findings", h.GetFindings)
		v1.GET("/findings/:id", h.GetFinding)
		v1.PATCH("/findings/:id/status", h.UpdateFindingStatus)
		v1.POST("/findings/:id/remediate", h.TriggerRemediation)
		v1.GET("/findings/:id/history", h.GetFindingHistory)

		// Jobs
		v1.GET("/jobs", h.GetJobs)
		v1.GET("/jobs/:id", h.GetJob)

		// Dashboard stats
		v1.GET("/stats", h.GetStats)

		// Notification recipients
		v1.GET("/recipients", h.GetRecipients)
		v1.POST("/recipients", h.AddRecipient)
		v1.DELETE("/recipients/:id", h.DeleteRecipient)

		// Audit log
		v1.GET("/audit", h.GetAuditLogs)
	}

	return r
}
