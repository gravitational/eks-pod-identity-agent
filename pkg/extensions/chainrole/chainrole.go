package chainrole

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/config"
	awsCreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

const (
	assumeRoleAnnotationPrefix     = "assume-role.ekspia.go.amzn.com/"
	sessionTagRoleAnnotationPrefix = assumeRoleAnnotationPrefix + "session-tag/"
)

type (
	roleAssumer interface {
		AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	}

	sessionConfigFunc func(ctx context.Context, awsCfg aws.Config, clusterName string, associationID string) (*sts.AssumeRoleInput, error)

	CredentialRetriever struct {
		delegate               credentials.CredentialRetriever
		jwtParser              *jwt.Parser
		roleAssumer            roleAssumer
		getSessionConfig       sessionConfigFunc
		reNamespaceFilter      *regexp.Regexp
		reServiceAccountFilter *regexp.Regexp
	}
)

func NewCredentialsRetriever(awsCfg aws.Config, eksCredentialsRetriever credentials.CredentialRetriever) *CredentialRetriever {
	cr := &CredentialRetriever{
		delegate:         eksCredentialsRetriever,
		jwtParser:        jwt.NewParser(),
		roleAssumer:      sts.NewFromConfig(awsCfg),
		getSessionConfig: getSessionConfigurationFromEKSPodIdentityTags,
	}

	log := logger.FromContext(context.TODO()).WithField("extension", "chainrole")

	if namespacePattern != "" {
		cr.reNamespaceFilter = regexp.MustCompile(namespacePattern)
		log = log.WithField("namespace_filter_regexp", cr.reNamespaceFilter.String())
	}

	if serviceAccountPattern != "" {
		cr.reServiceAccountFilter = regexp.MustCompile(serviceAccountPattern)
		log = log.WithField("serviceaccount_filter_regexp", cr.reServiceAccountFilter.String())
	}

	if namespacePattern == "" && serviceAccountPattern == "" {
		log.Info("Namespace/ServiceAccount filters are not provided. Extension is not enabled...")
	} else {
		log.Info("Enabled extension...")
	}

	return cr
}

func getSessionConfigurationFromEKSPodIdentityTags(ctx context.Context, awsCfg aws.Config, clusterName, associationID string) (*sts.AssumeRoleInput, error) {
	// Describe pod identity association to get tags
	podIdentityAssociation, err := eks.NewFromConfig(awsCfg).DescribePodIdentityAssociation(ctx,
		&eks.DescribePodIdentityAssociationInput{
			AssociationId: aws.String(associationID),
			ClusterName:   aws.String(clusterName),
		})
	if err != nil {
		return nil, fmt.Errorf("error describing pod identity association %s/%s: %w", clusterName, associationID, err)
	}

	assumeRoleInput := tagsToSTSAssumeRole(podIdentityAssociation.Association.Tags)

	if assumeRoleInput.RoleArn == nil {
		return nil, fmt.Errorf("couldn't get assume role arn from pod identity association tags %v", podIdentityAssociation.Association.Tags)
	}

	return assumeRoleInput, nil
}

func (c *CredentialRetriever) GetIamCredentials(ctx context.Context, request *credentials.EksCredentialsRequest) (
	*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	log := logger.FromContext(ctx).WithField("extension", "chainrole")

	// Get AWS EKS Pod Identity credentials as usual
	iamCredentials, responseMetadata, err := c.delegate.GetIamCredentials(ctx, request)
	if err != nil {
		return nil, nil, err
	}

	// Get Namespace and ServiceAccount names from JWT token
	ns, sa, err := c.serviceAccountFromJWT(request.ServiceAccountToken)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing JWT token: %w", err)
	}

	log = log.WithFields(logrus.Fields{
		"namespace":      ns,
		"serviceaccount": sa,
		"cluster-name":   request.ClusterName,
		"association-id": responseMetadata.AssociationId(),
	})

	// Check if Namespace/ServiceAccount filters configured
	// and do not proceed with role chaining if they don't match
	if !c.isEnabledFor(ns, sa) {
		log.Debug("namespace/serviceaccount do not match ChainRole filter. Skipping role chaining")
		return iamCredentials, responseMetadata, nil
	}

	// Assume eks pod identity credentials
	podIdentityCfg, err := config.LoadDefaultConfig(context.TODO(), config.WithCredentialsProvider(
		awsCreds.NewStaticCredentialsProvider(iamCredentials.AccessKeyId, iamCredentials.SecretAccessKey, iamCredentials.Token),
	))
	if err != nil {
		return nil, nil, fmt.Errorf("error loading pod identity credentials: %w", err)
	}

	// Assume new session based on the configurations provided in tags
	// session is assumed based on the IRSA credentials and NOT EKS Identity credentials
	// this is because EKS Identity credentials adds bunch of default tags
	// leaving no space for our custom tags https://github.com/aws/containers-roadmap/issues/2413
	assumeRoleInput, err := c.getSessionConfig(ctx, podIdentityCfg, request.ClusterName, responseMetadata.AssociationId())
	if err != nil {
		return nil, nil, fmt.Errorf("error getting session configuration: %w", err)
	}
	assumeRoleOutput, err := c.roleAssumer.AssumeRole(ctx, assumeRoleInput)
	if err != nil {
		return nil, nil, fmt.Errorf("error assuming role %s: %w", *assumeRoleInput.RoleArn, err)
	}

	log.WithField("assumed_role_arn", assumeRoleOutput.AssumedRoleUser.Arn).
		WithField("assumed_role_id", assumeRoleOutput.AssumedRoleUser.AssumedRoleId).
		WithField("source_identity", assumeRoleOutput.SourceIdentity).
		WithField("packed_policy_size", assumeRoleOutput.PackedPolicySize).
		Info("successfully assumed role")

	assumedCredentials, err := formatIAMCredentials(assumeRoleOutput)
	if err != nil {
		return nil, nil, fmt.Errorf("error formatting IAM credentials: %w", err)
	}

	return assumedCredentials, responseMetadata, nil
}

func (c *CredentialRetriever) isEnabledFor(namespace, serviceAccount string) bool {
	// at least one filter is required to enable chainrole logic,
	// otherwise it's disabled
	if c.reNamespaceFilter == nil && c.reServiceAccountFilter == nil {
		return false
	}

	namespaceMatch := c.reNamespaceFilter == nil || c.reNamespaceFilter.MatchString(namespace)
	serviceAccountMatch := c.reServiceAccountFilter == nil || c.reServiceAccountFilter.MatchString(serviceAccount)

	return namespaceMatch && serviceAccountMatch

}

func tagsToSTSAssumeRole(tags map[string]string) *sts.AssumeRoleInput {
	assumeRoleParams := &sts.AssumeRoleInput{}

	for key, value := range tags {
		if !strings.HasPrefix(key, assumeRoleAnnotationPrefix) {
			continue
		}

		param := strings.TrimPrefix(key, assumeRoleAnnotationPrefix)

		switch param {
		case "role-arn":
			assumeRoleParams.RoleArn = aws.String(value)
		case "role-session-name":
			assumeRoleParams.RoleSessionName = aws.String(value)
		case "source-identity":
			assumeRoleParams.SourceIdentity = aws.String(value)
		case "session-duration":
			duration, err := time.ParseDuration(value)
			if err != nil {
				break
			}
			assumeRoleParams.DurationSeconds = aws.Int32(int32(duration.Seconds()))
		}

		if strings.HasPrefix(key, sessionTagRoleAnnotationPrefix) {
			tagKey := strings.TrimPrefix(key, sessionTagRoleAnnotationPrefix)

			assumeRoleParams.Tags = append(assumeRoleParams.Tags, types.Tag{
				Key:   aws.String(tagKey),
				Value: aws.String(value),
			})
		}
	}

	return assumeRoleParams
}

func formatIAMCredentials(o *sts.AssumeRoleOutput) (*credentials.EksCredentialsResponse, error) {
	if o == nil || o.Credentials == nil || o.AssumedRoleUser == nil {
		return nil, errors.New("empty AssumeRole response")
	}

	parsedArn, err := arn.Parse(*o.AssumedRoleUser.Arn)
	if err != nil {
		return nil, fmt.Errorf("error parsing arn: %w", err)
	}

	return &credentials.EksCredentialsResponse{
		AccessKeyId:     aws.ToString(o.Credentials.AccessKeyId),
		SecretAccessKey: aws.ToString(o.Credentials.SecretAccessKey),
		Token:           aws.ToString(o.Credentials.SessionToken),
		AccountId:       parsedArn.AccountID,
		Expiration:      credentials.SdkCompliantExpirationTime{Time: *o.Credentials.Expiration},
	}, nil
}

func (c *CredentialRetriever) serviceAccountFromJWT(token string) (string, string, error) {
	parsedToken, _, err := c.jwtParser.ParseUnverified(token, &jwt.RegisteredClaims{})
	if err != nil {
		return "", "", fmt.Errorf("error parsing JWT token: %w", err)
	}

	subject, err := parsedToken.Claims.GetSubject()
	if err != nil {
		return "", "", fmt.Errorf("error reading JWT token subject: %w", err)
	}

	// subject is in the format: system:serviceaccount:<namespace>:<service_account>
	if !strings.HasPrefix(subject, "system:serviceaccount:") {
		return "", "", errors.New("JWT token claim subject doesn't start with 'system:serviceaccount:'")
	}

	subjectParts := strings.Split(subject, ":")
	if len(subjectParts) < 4 {
		return "", "", errors.New("invalid JWT token claim subject")
	}

	return subjectParts[2], subjectParts[3], nil
}
