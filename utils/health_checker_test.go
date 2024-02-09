package utils

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

// TestHelloWorldMessage tests the HelloWorldMessage function
func TestHelloWorldMessage(t *testing.T) {
	expected := "Hello, World!"
	actual := HelloWorldMessage()

	assert.Equal(t, expected, actual, "they should be equal")
}

// TestHealthCheckHandler tests the HealthCheckHandler
func TestHealthCheckHandler(t *testing.T) {
	// Set up a Gin router with the HealthCheckHandler
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	router.GET("/srv/hello", HealthCheckHandler)

	// Create a request to send to the handler
	req, _ := http.NewRequest("GET", "/srv/hello", nil)

	// Create a ResponseRecorder to record the response
	w := httptest.NewRecorder()

	// Serve the request to the router
	router.ServeHTTP(w, req)

	// Check if the status code is 200
	assert.Equal(t, http.StatusOK, w.Code)

	// Check if the response body contains the correct message
	expectedBody := `{"message":"Hello, World!"}`
	assert.JSONEq(t, expectedBody, w.Body.String())
}
