package serviceaccount

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// https://github.com/kubernetes/kubernetes/blob/master/pkg/serviceaccount/claims.go
type KubernetesIOClaims struct {
	Namespace      string             `json:"namespace"`
	Pod            *PodInfo           `json:"pod"`
	ServiceAccount ServiceAccountInfo `json:"serviceaccount"`
	WarnAfter      int64              `json:"warnafter"`
}

type PodInfo struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

type ServiceAccountInfo struct {
	Name string `json:"name"`
	UID  string `json:"uid"`
}

var jwtParser = jwt.NewParser()

func ServiceAccountFromJWT(token string) (*KubernetesIOClaims, string, error) {
	parsedToken, _, err := jwtParser.ParseUnverified(token, &jwt.RegisteredClaims{})
	if err != nil {
		return nil, "", fmt.Errorf("error parsing JWT token: %w", err)
	}

	subject, err := parsedToken.Claims.GetSubject()
	if err != nil {
		return nil, "", fmt.Errorf("error reading JWT token subject: %w", err)
	}

	if mapClaims, ok := parsedToken.Claims.(jwt.MapClaims); ok {
		if ik8s, ok := mapClaims["kubernetes.io"]; ok {
			if k8sClaims, ok := ik8s.(KubernetesIOClaims); ok {
				return &k8sClaims, subject, nil
			}
		}
	}

	return nil, subject, err
}
