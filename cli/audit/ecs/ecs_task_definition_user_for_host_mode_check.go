package ecs

import (
	"context"
	"fmt"
	"log"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/ecs/types"
)

// ECSTaskDefinitionUserForHostModeCheck checks for secure networking modes and user definitions in ECS task definitions.
func ECSTaskDefinitionUserForHostModeCheck(client *ecs.Client) {
	// List only active Task Definitions
	taskDefinitions, err := client.ListTaskDefinitions(context.TODO(), &ecs.ListTaskDefinitionsInput{
		Status: types.TaskDefinitionStatusActive, // Ensure only active task definitions are listed
	})
	if err != nil {
		log.Fatalf("[-] Unable to list task definitions: %v", err)
	}

	if len(taskDefinitions.TaskDefinitionArns) == 0 {
		fmt.Println("[PASS] No active task definitions found.")
		return
	}

	// Iterate through each task definition and describe its details
	for _, taskDefinitionArn := range taskDefinitions.TaskDefinitionArns {
		// Describe Task Definition
		taskDefinitionDetails, err := client.DescribeTaskDefinition(context.TODO(), &ecs.DescribeTaskDefinitionInput{
			TaskDefinition: aws.String(taskDefinitionArn),
		})
		if err != nil {
			log.Printf("[-] Unable to describe task definition %s: %v", taskDefinitionArn, err)
			continue
		}

		td := taskDefinitionDetails.TaskDefinition

		// Check if the task definition is using host network mode
		if td.NetworkMode == types.NetworkModeHost {
			fmt.Printf("Task Definition: %s is using Host Network Mode\n", taskDefinitionArn)

			// Check each container definition for privileged or user configurations
			for _, containerDef := range td.ContainerDefinitions {
				if containerDef.Privileged != nil && *containerDef.Privileged {
					fmt.Printf("  [-] Container %s has privileged access enabled (privileged=true)\n", *containerDef.Name)
				} else {
					fmt.Printf("  [+] Container %s does not have privileged access (privileged=false or undefined)\n", *containerDef.Name)
				}

				// Check if user is root or undefined
				if containerDef.User == nil || *containerDef.User == "root" {
					fmt.Printf("  [-] Container %s is running as root or user is not specified (user=root or empty)\n", *containerDef.Name)
				} else {
					fmt.Printf("  [+] Container %s is running with a non-root user (user=%s)\n", *containerDef.Name, *containerDef.User)
				}
			}
		} else {
			fmt.Printf("Task Definition: %s is using a secure network mode (Network Mode: %s)\n", taskDefinitionArn, td.NetworkMode)
		}
	}
}
