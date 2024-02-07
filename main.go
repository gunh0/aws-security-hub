package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"github.com/swaggo/swag/example/basic/docs"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		panic("Error loading .env file")
	}

	// Setup AWS Config
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

	// Create an Amazon S3 service client
	client := s3.NewFromConfig(cfg)
	if client != nil {
		log.Println("[+] Amazon S3 service client created successfully")
		// Print All Buckets
		buckets, err := client.ListBuckets(context.TODO(), &s3.ListBucketsInput{})
		if err != nil {
			log.Fatalf("[-] Unable to list buckets, %v", err)
		} else {
			log.Println("[+] Buckets:")
			for _, bucket := range buckets.Buckets {
				log.Println("  -", *bucket.Name)
			}
		}
	}

	r := gin.Default()
	docs.SwaggerInfo.BasePath = "/api/docs"

	serverUtils := r.Group("/srv")
	{
		// serverUtils.GET("/health", utils.healthCheckHandler)
		serverUtils.GET("/hello", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "World!",
			})
		})
	}

	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	r.Run(":8080")
}
