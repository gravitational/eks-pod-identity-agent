package serviceaccount

import (
	"context"
	"errors"
	"strings"
	"time"

	"go.amzn.com/eks/eks-pod-identity-agent/pkg/credentials"
	authV1 "k8s.io/api/authentication/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	k8s "k8s.io/client-go/kubernetes"
	typedauthV1 "k8s.io/client-go/kubernetes/typed/authentication/v1"
	listersV1 "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/rest"
)

type serviceAccountRetriever struct {
	lister        listersV1.ServiceAccountLister
	tokenReviewer typedauthV1.TokenReviewInterface
}

func NewSessionConfigRetriever() *serviceAccountRetriever {
	// Create a Kubernetes client
	config, err := rest.InClusterConfig()
	if err != nil {
		panic(err)
	}
	clientset, err := k8s.NewForConfig(config)
	if err != nil {
		panic(err)
	}

	return &serviceAccountRetriever{
		lister:        informers.NewSharedInformerFactory(clientset, time.Hour).Core().V1().ServiceAccounts().Lister(),
		tokenReviewer: clientset.AuthenticationV1().TokenReviews(),
	}
}

func (r *serviceAccountRetriever) GetSessionConfigMap(ctx context.Context, request *credentials.EksCredentialsRequest) (map[string]string, error) {
	ns, saName, err := r.validateToken(ctx, request.ServiceAccountToken)
	if err != nil {
		return nil, err
	}

	sa, err := r.lister.ServiceAccounts(ns).Get(saName)
	if err != nil {
		return nil, err
	}

	return sa.Annotations, nil
}

func (r *serviceAccountRetriever) validateToken(ctx context.Context, token string) (namespace, serviceaccount string, err error) {
	review, err := r.tokenReviewer.Create(ctx, &authV1.TokenReview{
		Spec: authV1.TokenReviewSpec{
			Token: token,
		},
	}, metaV1.CreateOptions{})
	if err != nil {
		return "", "", err
	}

	if !review.Status.Authenticated {
		return "", "", errors.New("token is invalid")
	}

	return ServiceAccountFromJWTSubject(review.Status.User.Username)
}

func ServiceAccountFromJWTSubject(jwtSubject string) (namespace, serviceAccount string, err error) {
	// subject is in the format: system:serviceaccount:<namespace>:<service_account>
	if !strings.HasPrefix(jwtSubject, "system:serviceaccount:") {
		return "", "", errors.New("JWT token claim subject doesn't start with 'system:serviceaccount:'")
	}

	subjectParts := strings.Split(jwtSubject, ":")
	if len(subjectParts) < 4 {
		return "", "", errors.New("invalid JWT token claim subject")
	}

	return subjectParts[2], subjectParts[3], nil
}
