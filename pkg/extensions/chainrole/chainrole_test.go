package chainrole

import (
	"context"
	"regexp"
	"sort"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
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
			g := NewWithT(t)
			got := tagsToSTSAssumeRole(tt.tags)
			sort.Slice(got.Tags, func(i, j int) bool {
				return *got.Tags[i].Key < *got.Tags[j].Key
			})
			g.Expect(got).To(Equal(tt.want))
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
			g := NewWithT(t)
			got, err := formatIAMCredentials(tt.assumeRole)
			if tt.wantErr {
				g.Expect(err).Error()
			} else {
				g.Expect(err).To(BeNil())
			}
			g.Expect(got).To(Equal(tt.want))
		})
	}
}

func TestCredentialRetriever_serviceAccountFromJWT(t *testing.T) {
	c := &CredentialRetriever{
		jwtParser: jwt.NewParser(),
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
			g := NewWithT(t)
			namespace, serviceaccount, err := c.serviceAccountFromJWT(tt.token)
			if tt.wantErr {
				g.Expect(err).Error()
			} else {
				g.Expect(err).To(BeNil())
			}
			g.Expect(namespace).To(Equal(tt.expectedNs))
			g.Expect(serviceaccount).To(Equal(tt.expectedSa))
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
	mockRoleAssumer            struct{}
	mockSessionConfigRetriever struct{}
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

func (m *mockSessionConfigRetriever) GetSessionConfigMap(ctx context.Context, request *credentials.EksCredentialsRequest) (map[string]string, error) {
	return map[string]string{}, nil
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
		name                  string
		req                   *credentials.EksCredentialsRequest
		want                  *credentials.EksCredentialsResponse
		delegateErr           error
		expectedDelegateCalls int
		wantErr               error
		namespaceFilter       string
		serviceaccountFilter  string
	}{
		{
			name: "Credentials request with no filter (chain logic skipped)",
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want:                  testDataAssumeRoleForPodIdentityCreds,
			expectedDelegateCalls: 1,
		},
		{
			name:            "Credentials request with namespace filter, no match (chain logic skipped)",
			namespaceFilter: `filter-that-will-not-match`,
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want:                  testDataAssumeRoleForPodIdentityCreds,
			expectedDelegateCalls: 1,
		},
		{
			name:                 "Credentials request with sa filter, no match (chain logic skipped)",
			serviceaccountFilter: `filter-that-will-not-match`,
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want:                  testDataAssumeRoleForPodIdentityCreds,
			expectedDelegateCalls: 1,
		},
		{
			name:                 "Credentials request with ns and sa filter, no match (chain logic skipped)",
			serviceaccountFilter: `filter-that-will-not-match`,
			namespaceFilter:      `filter-that-will-not-match`,
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want:                  testDataAssumeRoleForPodIdentityCreds,
			expectedDelegateCalls: 1,
		},
		{
			name:            "Credentials request with namespace filter (chaining role)",
			namespaceFilter: `test.*`,
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want: testDataAssumeRoleChainedCreds,
		},
		{
			name:                 "Credentials request with sa filter (chaining role)",
			serviceaccountFilter: `test.*`,
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want: testDataAssumeRoleChainedCreds,
		},
		{
			name:                 "Credentials request with ns and sa filter (chaining role)",
			serviceaccountFilter: `test.*`,
			namespaceFilter:      `test.*`,
			req: &credentials.EksCredentialsRequest{
				ClusterName:         "test-cluster-1",
				ServiceAccountToken: createTestToken("system:serviceaccount:test-namespace:test-service-account"),
			},
			want: testDataAssumeRoleChainedCreds,
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
			t.Cleanup(ctrl.Finish)

			re := func(pattern string) *regexp.Regexp {
				if pattern == "" {
					return nil
				}
				return regexp.MustCompile(pattern)
			}

			delegate := mockcreds.NewMockCredentialRetriever(ctrl)
			c := &CredentialRetriever{
				delegate:               delegate,
				jwtParser:              jwt.NewParser(),
				roleAssumer:            &mockRoleAssumer{},
				sessionConfigRetriever: &mockSessionConfigRetriever{},
				reNamespaceFilter:      re(tt.namespaceFilter),
				reServiceAccountFilter: re(tt.serviceaccountFilter),
			}

			delegate.EXPECT().GetIamCredentials(gomock.Any(), gomock.Any()).
				Return(testDataAssumeRoleForPodIdentityCreds, responseMetadataTest("test"), tt.delegateErr).Times(tt.expectedDelegateCalls)

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
