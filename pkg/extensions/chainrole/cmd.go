package chainrole

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	namespacePattern       string
	serviceAccountPattern  string
	sessionConfigSourceVal sessionConfigSource
)

func AddCMDFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&namespacePattern, "chainrole-namespace-pattern", "", "", "Namespace pattern to apply chain role functionality")
	cmd.Flags().StringVarP(&serviceAccountPattern, "chainrole-service-account-pattern", "", "", "Service account pattern to apply chain role functionality")
	cmd.Flags().Var(&sessionConfigSourceVal, "chainrole-session-config-source", fmt.Sprintf(`Source from where to get session configurations, must be %q or %q`, eksPodIdentityAssociationTags, serviceAccountAnnotations))
}

type sessionConfigSource string

const (
	eksPodIdentityAssociationTags = "eks-pod-identity-association-tags"
	serviceAccountAnnotations     = "service-account-annotations"
)

// String is used both by fmt.Print and by Cobra in help text
func (e *sessionConfigSource) String() string {
	return string(*e)
}

// Set must have pointer receiver so it doesn't change the value of a copy
func (e *sessionConfigSource) Set(v string) error {
	switch v {
	case eksPodIdentityAssociationTags, serviceAccountAnnotations:
		*e = sessionConfigSource(v)
		return nil
	default:
		return fmt.Errorf(`must be one of %q or %q`, eksPodIdentityAssociationTags, serviceAccountAnnotations)
	}
}

// Type is only used in help text
func (e *sessionConfigSource) Type() string {
	return "session-config-source"
}
