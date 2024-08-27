package chainrole

import (
	"context"
	"reflect"
	"regexp"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	eksauthTypes "github.com/aws/aws-sdk-go-v2/service/eksauth/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/aws-sdk-go-v2/service/sts/types"
	"github.com/golang-jwt/jwt/v5"
	. "github.com/onsi/gomega"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/middleware/logger"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials/mockcreds"
	"go.uber.org/mock/gomock"
)

func Test_tagsToSTSAssumeRole(t *testing.T) {
	tests := []struct {
		name string
		tags map[string]string
		want *sts.AssumeRoleInput
	}{
		{
			name: "Valid tags",
			tags: map[string]string{
				"assume-role.ekspia.go.amzn.com/role-arn":             "arn:partition:service:region:account-id:resource-id",
				"assume-role.ekspia.go.amzn.com/role-session-name":    "role-session-name",
				"assume-role.ekspia.go.amzn.com/session-duration":     "1h",
				"assume-role.ekspia.go.amzn.com/source-identity":      "test-namespace",
				"assume-role.ekspia.go.amzn.com/session-tag/TestTag1": "test-value-1",
				"assume-role.ekspia.go.amzn.com/session-tag/TestTag2": "test-value-2",
			},
			want: &sts.AssumeRoleInput{
				RoleArn:         aws.String("arn:partition:service:region:account-id:resource-id"),
				RoleSessionName: aws.String("role-session-name"),
				DurationSeconds: aws.Int32(3600),
				SourceIdentity:  aws.String("test-namespace"),
				Tags: []types.Tag{
					{Key: aws.String("TestTag1"), Value: aws.String("test-value-1")},
					{Key: aws.String("TestTag2"), Value: aws.String("test-value-2")},
				},
			},
		},
		{
			name: "Wrong tag key prefix",
			tags: map[string]string{
				"role.ekspia.go.amzn.com/role-arn":             "arn:partition:service:region:account-id:resource-id",
				"role.ekspia.go.amzn.com/role-session-name":    "role-session-name",
				"role.ekspia.go.amzn.com/session-duration":     "1h",
				"role.ekspia.go.amzn.com/source-identity":      "test-namespace",
				"role.ekspia.go.amzn.com/session-tag/TestTag1": "test-value-1",
				"role.ekspia.go.amzn.com/session-tag/TestTag2": "test-value-2",
			},
			want: &sts.AssumeRoleInput{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tagsToSTSAssumeRole(tt.tags); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("tagsToSTSAssumeRole() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_formatIAMCredentials(t *testing.T) {
	tests := []struct {
		name       string
		assumeRole *sts.AssumeRoleOutput
		want       *credentials.EksCredentialsResponse
		wantErr    bool
	}{
		{
			name: "Valid credentials format",
			assumeRole: &sts.AssumeRoleOutput{
				AssumedRoleUser: &types.AssumedRoleUser{
					Arn: aws.String("arn:partition:service:region:account-id:resource-id"),
				},
				Credentials: &types.Credentials{
					AccessKeyId:     aws.String("access_key_id"),
					SecretAccessKey: aws.String("secret_access_key"),
					SessionToken:    aws.String("session_token"),
					Expiration:      aws.Time(time.Time{}),
				},
			},
			want: &credentials.EksCredentialsResponse{
				AccessKeyId:     "access_key_id",
				SecretAccessKey: "secret_access_key",
				Token:           "session_token",
				Expiration:      credentials.SdkCompliantExpirationTime{Time: time.Time{}},
				AccountId:       "account-id",
			},
		},
		{
			name: "Bad arn",
			assumeRole: &sts.AssumeRoleOutput{
				AssumedRoleUser: &types.AssumedRoleUser{
					Arn: aws.String("not valid arn"),
				},
			},
			wantErr: true,
		},
		{
			name: "Nil credentials",
			assumeRole: &sts.AssumeRoleOutput{
				AssumedRoleUser: &types.AssumedRoleUser{
					Arn: aws.String("arn:partition:service:region:account-id:resource-id"),
				},
				Credentials: nil,
			},
			wantErr: true,
		},
		{
			name: "Nil AssumedRole",
			assumeRole: &sts.AssumeRoleOutput{
				AssumedRoleUser: nil,
				Credentials: &types.Credentials{
					AccessKeyId:     aws.String("access_key_id"),
					SecretAccessKey: aws.String("secret_access_key"),
					SessionToken:    aws.String("session_token"),
					Expiration:      aws.Time(time.Time{}),
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := formatIAMCredentials(tt.assumeRole)
			if (err != nil) != tt.wantErr {
				t.Errorf("formatIAMCredentials() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("formatIAMCredentials() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCredentialRetriever_serviceAccountFromJWT(t *testing.T) {
	c := &CredentialRetriever{
		jwtParser: jwt.NewParser(),
	}

	type args struct {
		token string
	}
	tests := []struct {
		name       string
		token      string
		expectedNs string
		expectedSa string
		wantErr    bool
	}{
		{
			name:       "Test valid token",
			token:      createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			expectedNs: "test-namespace",
			expectedSa: "test-service-account",
		},
		{
			name:    "Test invalid token",
			token:   createTestToken("test-namespace:test-service-account"),
			wantErr: true,
		},
		{
			name:    "Test missing subject",
			token:   createTestToken(""),
			wantErr: true,
		},
		{
			name:    "Test missing service account",
			token:   createTestToken("system:serviceaccount:test-namespace"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			namespace, serviceaccount, err := c.serviceAccountFromJWT(tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("CredentialRetriever.serviceAccountFromJWT() error = %v", err)
				return
			}
			if namespace != tt.expectedNs {
				t.Errorf("CredentialRetriever.serviceAccountFromJWT() got = %v, want %v", namespace, tt.expectedNs)
			}
			if serviceaccount != tt.expectedSa {
				t.Errorf("CredentialRetriever.serviceAccountFromJWT() got1 = %v, want %v", serviceaccount, tt.expectedSa)
			}
		})
	}
}

func createTestToken(subject string) string {
	token, _ := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		NotBefore: jwt.NewNumericDate(time.Now()),
		Issuer:    "some-issuer",
		Subject:   subject,
		Audience:  []string{"some-audience"},
	}).SignedString([]byte("signingKey"))

	return token
}

type (
	mockRoleAssumer       struct{}
	mockSessionConfigurer struct{}
)

func (m *mockRoleAssumer) AssumeRole(ctx context.Context, params *sts.AssumeRoleInput, optFns ...func(*sts.Options)) (*sts.AssumeRoleOutput, error) {
	return &sts.AssumeRoleOutput{
		AssumedRoleUser: &types.AssumedRoleUser{
			Arn: aws.String("arn:partition:service:region:assumed_account_id:resource-id"),
		},
		Credentials: &types.Credentials{
			AccessKeyId:     aws.String("assumed_access_key_id"),
			SecretAccessKey: aws.String("assumed_secret_access_key"),
			SessionToken:    aws.String("assumed_session_token"),
			Expiration:      aws.Time(time.Time{}),
		},
	}, nil
}

func (m *mockSessionConfigurer) GetSessionConfiguration(ctx context.Context, awsCfg aws.Config, clusterName string, associationID string) (*sts.AssumeRoleInput, error) {
	return &sts.AssumeRoleInput{}, nil
}

type responseMetadataTest string

func (receiver responseMetadataTest) AssociationId() string {
	return string(receiver)
}

func TestCredentialRetriever_GetIamCredentials(t *testing.T) {
	testDataAssumeRoleForPodIdentityCreds := &credentials.EksCredentialsResponse{
		AccessKeyId:     "pod_identity_key",
		SecretAccessKey: "pod_identity_secret",
		Token:           "pod_identity_token",
		Expiration:      credentials.SdkCompliantExpirationTime{Time: time.Time{}},
		AccountId:       "pod_identity_account",
	}

	testDataAssumeRoleChainedCreds := &credentials.EksCredentialsResponse{
		AccessKeyId:     "assumed_access_key_id",
		SecretAccessKey: "assumed_secret_access_key",
		Token:           "assumed_session_token",
		Expiration:      credentials.SdkCompliantExpirationTime{Time: time.Time{}},
		AccountId:       "assumed_account_id",
	}

	logger.Initialize("DEBUG")

	tests := []struct {
		name                 string
		req                  *credentials.EksCredentialsRequest
		want                 *credentials.EksCredentialsResponse
		delegateErr          error
		wantErr              error
		namespaceFilter      string
		serviceaccountFilter string
	}{
		{
			name: "Credentials request with no filter",
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want: testDataAssumeRoleChainedCreds,
		},
		{
			name:            "Credentials request with namespace filter, no match",
			namespaceFilter: `filter-that-will-not-match`,
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want: testDataAssumeRoleForPodIdentityCreds,
		},
		{
			name:                 "Credentials request with sa filter, no match",
			serviceaccountFilter: `filter-that-will-not-match`,
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want: testDataAssumeRoleForPodIdentityCreds,
		},
		{
			name:                 "Credentials request with ns and sa filter, no match",
			serviceaccountFilter: `filter-that-will-not-match`,
			namespaceFilter:      `filter-that-will-not-match`,
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want: testDataAssumeRoleForPodIdentityCreds,
		},
		{
			name:            "Credentials request with namespace filter",
			namespaceFilter: `test.*`,
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want: testDataAssumeRoleChainedCreds,
		},
		{
			name:                 "Credentials request with sa filter",
			serviceaccountFilter: `test.*`,
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want: testDataAssumeRoleChainedCreds,
		},
		{
			name:                 "Credentials request with ns and sa filter",
			serviceaccountFilter: `test.*`,
			namespaceFilter:      `test.*`,
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want: testDataAssumeRoleChainedCreds,
		},
		{
			name:        "Invalid Pod Identity Token",
			req:         &credentials.EksCredentialsRequest{},
			delegateErr: &eksauthTypes.InvalidTokenException{},
			wantErr:     &eksauthTypes.InvalidTokenException{},
		},
		{
			name:        "Expired Pod Identity Token",
			req:         &credentials.EksCredentialsRequest{},
			delegateErr: &eksauthTypes.ExpiredTokenException{},
			wantErr:     &eksauthTypes.ExpiredTokenException{},
		},
		{
			name:        "SA Unavailable Exception",
			req:         &credentials.EksCredentialsRequest{},
			delegateErr: &eksauthTypes.ServiceUnavailableException{},
			wantErr:     &eksauthTypes.ServiceUnavailableException{},
		},
		{
			name:        "Access Denied Exception",
			req:         &credentials.EksCredentialsRequest{},
			delegateErr: &eksauthTypes.AccessDeniedException{},
			wantErr:     &eksauthTypes.AccessDeniedException{},
		},
		{
			name: "Invalid token",
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: "this is not real token",
			},
			wantErr: jwt.ErrTokenMalformed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g := NewWithT(t)
			ctrl := gomock.NewController(t)
			reNamespaceFilter = regexp.MustCompile(tt.namespaceFilter)
			reServiceAccountFilter = regexp.MustCompile(tt.serviceaccountFilter)

			t.Cleanup(func() {
				ctrl.Finish()
				reNamespaceFilter = nil
				reServiceAccountFilter = nil
			})

			delegate := mockcreds.NewMockCredentialRetriever(ctrl)
			c := &CredentialRetriever{
				delegate:             delegate,
				jwtParser:            jwt.NewParser(),
				roleAssumer:          &mockRoleAssumer{},
				awsSessionConfigurer: &mockSessionConfigurer{},
			}

			delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
				Return(testDataAssumeRoleForPodIdentityCreds, responseMetadataTest("test"), tt.delegateErr).Times(1)

			got, _, err := c.GetIamCredentials(context.TODO(), tt.req)
			if tt.wantErr != nil {
				g.Expect(err).To(MatchError(tt.wantErr))
			} else {
				g.Expect(err).To(BeNil())
			}
			g.Expect(got).To(Equal(tt.want))
		})
	}
}
