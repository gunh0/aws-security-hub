package ecs

import (
	"context"
	"fmt"
	"net/http"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/gin-gonic/gin"
)

// ECSTaskDefinitionUserForHostModeCheck checks for secure networking modes and user definitions in ECS task definitions.
func ECSTaskDefinitionUserForHostModeCheck(cfg aws.Config) string {
	// Create an ECS service client
	client := ecs.NewFromConfig(cfg)

	// List Task Definitions
	taskDefinitions, err := client.ListTaskDefinitions(context.Background(), &ecs.ListTaskDefinitionsInput{})
	if err != nil {
		return fmt.Sprintf("[-] Unable to list task definitions: %v", err)
	}

	var resultMsg string
	for _, taskDefinition := range taskDefinitions.TaskDefinitionArns {
		// Describe Task Definition
		taskDefinitionDetails, err := client.DescribeTaskDefinition(context.Background(), &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: aws.String(taskDefinition),
		})
		if err != nil {
			return fmt.Sprintf("[-] Unable to describe task definition %s: %v", *aws.String(taskDefinition), err)
		}

		// Assuming the intention is to log the network mode and IPC mode (User field seems to be mistakenly referred to as IpcMode)
		resultMsg += fmt.Sprintf("Task Definition: %s\n  - Network Mode: %s\n  - IPC Mode: %s\n", *aws.String(taskDefinition), taskDefinitionDetails.TaskDefinition.NetworkMode, taskDefinitionDetails.TaskDefinition.IpcMode)
	}

	if resultMsg == "" {
		resultMsg = "No task definitions found."
	}

	return resultMsg
}

// ECSTaskDefinitionUserForHostModeCheckHandler godoc
// @Summary Checks for secure networking modes and user definitions in ECS task definitions.
// @Description Checks for secure networking modes and user definitions in ECS task definitions.
// @Tags ECS
// @Produce  json
// @Success 200
// @Router /ecs/ecs-task-definition-user-for-host-mode-check [get]
func ECSTaskDefinitionUserForHostModeCheckHandler(cfg aws.Config, c *gin.Context) {
	resultMsg := ECSTaskDefinitionUserForHostModeCheck(cfg)
	c.JSON(http.StatusOK, gin.H{"result": resultMsg})
}
