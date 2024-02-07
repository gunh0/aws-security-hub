package main

import (
	"context"
	"log"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/gin-gonic/gin"
	docs "github.com/gunh0/aws-security-hub/docs"
	utils "github.com/gunh0/aws-security-hub/utils"
	"github.com/joho/godotenv"
	swaggerfiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
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

	serverUtils := r.Group("/srv")
	{
		serverUtils.GET("/hello", utils.HealthCheckHandler)
	}

	docs.SwaggerInfo.Title = "AWS Security Hub Utils"
	docs.SwaggerInfo.BasePath = "/"
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerfiles.Handler))
	r.Run(":8080")
}
