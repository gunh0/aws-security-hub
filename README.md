# AWS Security Hub

Automatic Audit & CSPM (Cloud Security Posture Management) tool written in Go, referencing [AWS Security Hub Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html).

This tool performs automatic security audits on your AWS resources, including but not limited to EC2 security groups, EBS snapshots, and ECS task definitions, based on best practices and compliance frameworks. It leverages the AWS SDK and allows easy auditing via CLI commands.

The ultimate goal is to implement all controls as specified in the [AWS Security Hub Controls Reference](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html), continuously updating the tool to cover more AWS services and security controls.

### Features

This tool will provide comprehensive audit capabilities across the following AWS services and security controls:

- **Security Hub controls for AWS accounts**
- **Amazon API Gateway controls**
  - [x] [APIGateway.1] API Gateway REST and WebSocket API execution logging should be enabled
  - [x] [APIGateway.2] API Gateway REST API stages should be configured to use SSL certificates for backend authentication
- **Security Hub controls for AWS AppSync**
- **Security Hub controls for Athena**
- **Security Hub controls for AWS Backup**
- **Security Hub controls for ACM (AWS Certificate Manager)**
- **Security Hub controls for AWS CloudFormation**
- **Security Hub controls for CloudFront**
- **Security Hub controls for CloudTrail**
- **Security Hub controls for CloudWatch**
- **Security Hub controls for CodeArtifact**
- **Security Hub controls for CodeBuild**
- **Security Hub controls for AWS Config**
- **Security Hub controls for Amazon Data Firehose**
- **Security Hub controls for DataSync**
- **Security Hub controls for Detective**
- **Security Hub controls for AWS DMS (Database Migration Service)**
- **Amazon DocumentDB controls**
  - [x] [DocumentDB.1] Amazon DocumentDB clusters should be encrypted at rest
  - [x] [DocumentDB.2] Amazon DocumentDB clusters should have an adequate backup retention period
  - [x] [DocumentDB.3] Amazon DocumentDB manual cluster snapshots should not be public
  - [x] [DocumentDB.4] Amazon DocumentDB clusters should publish audit logs to CloudWatch Logs
- **Security Hub controls for DynamoDB**
- **Amazon EC2 controls**
  - [x] [EC2.1] Amazon EBS snapshots should not be publicly restorable
- **Security Hub controls for Auto Scaling**
- **Security Hub controls for Amazon ECR**
- **Security Hub controls for Amazon ECS**
- **Security Hub controls for Amazon EFS**
- **Security Hub controls for Amazon EKS**
- **Security Hub controls for ElastiCache**
- **Security Hub controls for Elastic Beanstalk**
- **Security Hub controls for Elastic Load Balancing**
- **Security Hub controls for Elasticsearch (OpenSearch)**
- **Security Hub controls for Amazon EMR**
- **Security Hub controls for EventBridge**
- **Security Hub controls for Amazon FSx**
- **Security Hub controls for Global Accelerator**
- **Security Hub controls for AWS Glue**
- **Security Hub controls for GuardDuty**
- **Security Hub controls for IAM (Identity and Access Management)**
- **Security Hub controls for Amazon Inspector**
- **Security Hub controls for AWS IoT**
- **Security Hub controls for Kinesis**
- **Security Hub controls for AWS KMS (Key Management Service)**
- **Security Hub controls for Lambda**
- **Security Hub controls for Macie**
- **Security Hub controls for Amazon MSK (Managed Streaming for Apache Kafka)**
- **Security Hub controls for Amazon MQ**
- **Security Hub controls for Neptune**
- **Security Hub controls for Network Firewall**
- **Security Hub controls for OpenSearch Service**
- **Security Hub controls for AWS Private CA**
- **Security Hub controls for Amazon RDS**
- **Security Hub controls for Amazon Redshift**
- **Security Hub controls for Route 53**
- **Security Hub controls for Amazon S3**
- **Security Hub controls for SageMaker**
- **Security Hub controls for Secrets Manager**
- **Security Hub controls for Service Catalog**
- **Security Hub controls for Amazon SES (Simple Email Service)**
- **Security Hub controls for Amazon SNS (Simple Notification Service)**
- **Security Hub controls for Amazon SQS (Simple Queue Service)**
- **Security Hub controls for Step Functions**
- **Security Hub controls for Systems Manager**
- **Security Hub controls for Transfer Family**
- **Security Hub controls for AWS WAF (Web Application Firewall)**
- **Security Hub controls for WorkSpaces**

As of now, the tool supports some key controls, including EC2, EBS, and ECS audits. More services and controls will be added over time, following the official AWS Security Hub guidelines.

<br/>

### Prerequisites

- Go 1.22.4 (Currently, the tool is tested with Go 1.22.4)
- AWS credentials (Access Key ID, Secret Access Key) with appropriate permissions

Ensure that AWS credentials are properly configured via environment variables or an `.env` file in the root of the project:

```bash
AWS_ACCESS_KEY_ID=your-access-key-id
AWS_SECRET_ACCESS_KEY=your-secret-access-key
AWS_REGION=ap-northeast-2
```

The default region is set to ap-northeast-2 (South Korea), but you can change this in the .env file or by using the AWS_REGION environment variable.

<br/>

### Commands

The tool provides several CLI commands to audit different AWS resources. Below are the available commands:

**Example 1. Check EC2 Security Groups for Unrestricted Access (EC2.19)**

```bash
go run main.go restricted-common-ports
```

Or, using the alias:

```bash
go run main.go ec2.19
````

This command checks for unrestricted access to high-risk ports in EC2 security groups.

**Example 2. Check EBS Snapshots for Public Restorability (EC2.1)**

```bash
go run main.go ebs-snapshot-public-restorable-check
```

Or, using the alias:

```bash
go run main.go ec2.1
```

<br/>

### Continuous Updates

Our goal is to implement all security controls as defined by the AWS Security Hub Controls Reference. Currently, the tool supports EC2, EBS, and ECS audits, but it will be continuously updated to cover more services and controls as listed in the features section.

This tool will eventually provide a comprehensive audit system based on the full set of AWS Security Hub controls found here.

<br/>

### Adding New Audit Rules

This tool is easily extensible. You can add new audit rules by creating a new Go file under the appropriate AWS service directory (e.g., audit/ec2 or audit/ecs) and registering the new audit rule as a command in main.go.
