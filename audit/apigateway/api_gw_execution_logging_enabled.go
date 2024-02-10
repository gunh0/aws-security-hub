package apigateway

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/apigateway"
	"github.com/gin-gonic/gin"
)

// APIGWExecutionLoggingEnabled checks if logging is enabled for all stages of API Gateway REST or WebSocket APIs.
// The control passes if the loggingLevel is either ERROR or INFO for all stages.
func APIGWExecutionLoggingEnabled(cfg aws.Config) (string, string) {
	// Create an API Gateway service client
	client := apigateway.NewFromConfig(cfg)

	// List APIs
	apis, err := client.GetRestApis(context.Background(), &apigateway.GetRestApisInput{})
	if err != nil {
		return "FAIL", fmt.Sprintf("[-] Unable to list APIs: %v", err)
	}

	var result string = "PASS"
	var resultMsg string
	for _, api := range apis.Items {
		// Get the list of stages for the API
		stages, err := client.GetStages(context.Background(), &apigateway.GetStagesInput{
			RestApiId: api.Id,
		})
		if err != nil {
			return "FAIL", fmt.Sprintf("[-] Unable to get stages for API %s: %v", *api.Name, err)
		}

		for _, stage := range stages.Item {
			// Get stage settings, including execution logging settings
			stageDetails, err := client.GetStage(context.Background(), &apigateway.GetStageInput{
				RestApiId: api.Id,
				StageName: stage.StageName,
			})

			if err != nil {
				return "FAIL", fmt.Sprintf("[-] Unable to get stage details for API %s, Stage %s: %v", *api.Name, *stage.StageName, err)
			}

			loggingEnabled := false
			if stageDetails.MethodSettings != nil {
				for _, methodSetting := range stageDetails.MethodSettings {
					// Check if logging level is ERROR or INFO
					if methodSetting.LoggingLevel != nil && (*methodSetting.LoggingLevel == "ERROR" || *methodSetting.LoggingLevel == "INFO") {
						loggingEnabled = true
					}
				}
			}

			if !loggingEnabled {
				result = "FAIL" // Mark as FAIL if logging is not properly enabled
				resultMsg = fmt.Sprintf("[-] Logging is not properly enabled for API %s on stage %s", *api.Name, *stage.StageName)
				return result, resultMsg // Fail immediately if any stage doesn't meet the criteria
			}
		}
	}

	if result == "PASS" {
		resultMsg = "[+] All APIs and stages have proper logging enabled."
	}

	return result, resultMsg
}

// APIGWExecutionLoggingEnabledHandler godoc
// @Summary Checks if logging is enabled for all stages of API Gateway REST or WebSocket APIs.
// @Description Checks if logging is enabled for all stages of API Gateway REST or WebSocket APIs.
// @Tags APIGateway
// @Produce  json
// @Success 200
// @Router /apigateway/api-gw-execution-logging-enabled [get]
func APIGWExecutionLoggingEnabledHandler(cfg aws.Config, c *gin.Context) {
	result, resultMsg := APIGWExecutionLoggingEnabled(cfg)
	c.JSON(http.StatusOK, gin.H{"result": result, "message": resultMsg})
}
