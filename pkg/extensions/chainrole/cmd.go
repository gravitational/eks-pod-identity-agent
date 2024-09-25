package chainrole

import (
	"github.com/spf13/cobra"
)

var (
	namespacePattern      string
	serviceAccountPattern string
)

func AddCMDFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&namespacePattern, "chainrole-namespace-pattern", "", "", "Namespace pattern to apply chain role functionality")
	cmd.Flags().StringVarP(&serviceAccountPattern, "chainrole-service-account-pattern", "", "", "Service account pattern to apply chain role functionality")
}
