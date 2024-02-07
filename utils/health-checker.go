package utils

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func HelloWorldMessage() string {
	return "Hello, World!"
}

// HealthCheckHandler godoc
// @Summary Health Check
// @Description Server Health Check
// @Tags Server Utils
// @Accept json
// @Produce json
// @Success 200
// @Router /srv/hello [get]
func HealthCheckHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"message": HelloWorldMessage(),
	})
}
