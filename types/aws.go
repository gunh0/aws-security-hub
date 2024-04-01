// types/aws.go
package types

import (
	"github.com/aws/aws-sdk-go-v2/aws"
)

// AWSClient wraps the AWS SDK config
type AWSClient struct {
	Config aws.Config
}

// AWSClientInitializer defines a function type for initializing AWS client
type AWSClientInitializer func() (*AWSClient, error)
