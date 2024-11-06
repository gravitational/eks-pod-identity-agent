package ekspodidentities

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	awsCreds "github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	"go.amzn.com/eks/eks-pod-identity-agent/internal/cloud/eksauth"
	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
)

type podIdentityAssociationRetriever struct {
	eksAuth eksauth.Iface
}

func NewSessionConfigRetriever(eksAuth eksauth.Iface) *podIdentityAssociationRetriever {
	return &podIdentityAssociationRetriever{eksAuth}
}

func (r *podIdentityAssociationRetriever) GetSessionConfigMap(ctx context.Context, request *credentials.EksCredentialsRequest) (map[string]string, error) {
	resp, metadata, err := r.eksAuth.GetIamCredentials(ctx, request)
	if err != nil {
		return nil, err
	}

	// Assume eks pod identity credentials
	podIdentityCfg, err := config.LoadDefaultConfig(context.TODO(), config.WithCredentialsProvider(
		awsCreds.NewStaticCredentialsProvider(resp.AccessKeyId, resp.SecretAccessKey, resp.Token),
	))
	if err != nil {
		return nil, fmt.Errorf("error loading pod identity credentials: %w", err)
	}

	clusterName, associationID := metadata.AssociationId(), request.ClusterName

	podIdentityAssociation, err := eks.NewFromConfig(podIdentityCfg).DescribePodIdentityAssociation(ctx,
		&eks.DescribePodIdentityAssociationInput{
			AssociationId: aws.String(associationID),
			ClusterName:   aws.String(clusterName),
		})
	if err != nil {
		return nil, fmt.Errorf("error describing pod identity association %s/%s: %w", clusterName, associationID, err)
	}

	return podIdentityAssociation.Association.Tags, nil

}
