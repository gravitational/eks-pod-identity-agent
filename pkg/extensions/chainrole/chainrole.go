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
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/extensions/chainrole/ekspodidentities"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/extensions/chainrole/serviceaccount"
)

const (
	assumeRoleAnnotationPrefix     = "assume-role.ekspia.go.amzn.com/"
	sessionTagRoleAnnotationPrefix = assumeRoleAnnotationPrefix + "session-tag/"
	// service account annotations doesn't support more than one "/"
	sessionTagRoleAnnotationPrefix2 = assumeRoleAnnotationPrefix + "session-tag-"
)

type (
	roleAssumer interface {
		AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error)
	}

	sessionConfigRetriever interface {
		GetSessionConfigMap(ctx context.Context, request *credentials.EksCredentialsRequest) (map[string]string, error)
	}

	CredentialRetriever struct {
		delegate               credentials.CredentialRetriever
		jwtParser              *jwt.Parser
		roleAssumer            roleAssumer
		sessionConfigRetriever sessionConfigRetriever
		reNamespaceFilter      *regexp.Regexp
		reServiceAccountFilter *regexp.Regexp
	}
)

func NewCredentialsRetriever(awsCfg aws.Config, eksCredentialsRetriever credentials.CredentialRetriever) *CredentialRetriever {
	cr := &CredentialRetriever{
		delegate:    eksCredentialsRetriever,
		jwtParser:   jwt.NewParser(),
		roleAssumer: sts.NewFromConfig(awsCfg),
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

	switch sessionConfigSourceVal {
	case eksPodIdentityAssociationTags:
		cr.sessionConfigRetriever = ekspodidentities.NewSessionConfigRetriever(eksCredentialsRetriever)
	case serviceAccountAnnotations:
		cr.sessionConfigRetriever = serviceaccount.NewSessionConfigRetriever()
	default:
	}

	return cr
}

func (c *CredentialRetriever) GetIamCredentials(ctx context.Context, request *credentials.EksCredentialsRequest) (
	*credentials.EksCredentialsResponse, credentials.ResponseMetadata, error) {
	log := logger.FromContext(ctx).WithField("extension", "chainrole")

	// Get Namespace and ServiceAccount names from JWT token
	ns, sa, err := c.serviceAccountFromJWT(request.ServiceAccountToken)
	if err != nil {
		return nil, nil, fmt.Errorf("error parsing JWT token: %w", err)
	}

	// Check if Namespace/ServiceAccount filters configured
	// and do not proceed with role chaining if they don't match
	if !c.isEnabledFor(ns, sa) {
		log.Debug("namespace/serviceaccount do not match ChainRole filter. Skipping role chaining")
		return c.delegate.GetIamCredentials(ctx, request)
	}

	log = log.WithFields(logrus.Fields{
		"namespace":      ns,
		"serviceaccount": sa,
		"cluster-name":   request.ClusterName,
	})

	sessionConfigMap, err := c.sessionConfigRetriever.GetSessionConfigMap(ctx, request)
	if err != nil {
		return nil, nil, err
	}

	assumeRoleInput := tagsToSTSAssumeRole(sessionConfigMap)
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

	return assumedCredentials, nil, nil
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

		if strings.HasPrefix(key, sessionTagRoleAnnotationPrefix) || strings.HasPrefix(key, sessionTagRoleAnnotationPrefix2) {
			tagKey := strings.TrimPrefix(key, sessionTagRoleAnnotationPrefix)
			tagKey = strings.TrimPrefix(tagKey, sessionTagRoleAnnotationPrefix2)

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

func (c *CredentialRetriever) serviceAccountFromJWT(token string) (ns string, sa string, err error) {
	claims, subject, err := serviceaccount.ServiceAccountFromJWT(token)
	if err != nil {
		return "", "", fmt.Errorf("error parsing JWT token: %w", err)
	}

	if claims != nil && claims.Namespace != "" && claims.ServiceAccount.Name != "" {
		return claims.Namespace, claims.ServiceAccount.Name, nil
	}

	return serviceaccount.ServiceAccountFromJWTSubject(subject)
}
