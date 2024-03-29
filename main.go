package main

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	audit "github.com/gunh0/aws-security-hub/audit"
	docs "github.com/gunh0/aws-security-hub/docs"
	utils "github.com/gunh0/aws-security-hub/utils"
	"github.com/joho/godotenv"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// setupAWSSDK initializes the AWS SDK configuration.
func setupAWSSDK() aws.Config {
	// Load AWS configuration with region and credentials.
	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithRegion(os.Getenv("AWS_REGION")),
		config.WithCredentialsProvider(aws.NewCredentialsCache(aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
			return aws.Credentials{
				AccessKeyID:     os.Getenv("AWS_ACCESS_KEY_ID"),
				SecretAccessKey: os.Getenv("AWS_SECRET_ACCESS_KEY"),
			}, nil
		}))),
	)
	if err != nil {
		log.Fatalf("[-] Unable to load SDK config, %v", err)
	} else {
		log.Println("[+] AWS SDK Config loaded successfully")
	}
	return cfg
}

// initializeRoutes sets up the routes for the Gin server.
func initializeRoutes(r *gin.Engine, cfg aws.Config) {
	// Health check route
	serverUtils := r.Group("/srv")
	{
		serverUtils.GET("/hello", utils.HealthCheckHandler)
	}

	// ECS specific routes
	ecsGroup := r.Group("/ecs")
	{
		ecsGroup.GET("/ecs-task-definition-user-for-host-mode-check", func(c *gin.Context) {
			audit.ECSTaskDefinitionUserForHostModeCheckHandler(cfg, c)
		})
	}

	// Setup Swagger documentation
	docs.SwaggerInfo.Title = "AWS Security Hub Utils"
	docs.SwaggerInfo.BasePath = "/"
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
}

func main() {
	if err := godotenv.Load(); err != nil {
		log.Fatalf("Error loading .env file: %v", err)
	}

	// Setup AWS SDK
	cfg := setupAWSSDK()

	// Create an Amazon S3 service client and list buckets as a test
	client := s3.NewFromConfig(cfg)
	buckets, err := client.ListBuckets(context.Background(), &s3.ListBucketsInput{})
	if err != nil {
		log.Fatalf("Unable to list buckets: %v", err)
	}
	log.Println("Buckets:")
	for _, bucket := range buckets.Buckets {
		log.Printf("  - %s", *bucket.Name)
	}

	// Initialize Gin server
	r := gin.Default()
	initializeRoutes(r, cfg)

	// Start the server
	if err := r.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}
