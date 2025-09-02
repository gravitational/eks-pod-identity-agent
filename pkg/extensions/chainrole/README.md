# Role chaining extension

This extensions allows to use [Role Chaining](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html#iam-term-role-chaining) to Assume different role
before sharing credentials with requesting container.

## Why

This functionality will enable following features:
- Cross Account Assume Role 
- Customization of Role Session Name, Role Session Tags, etc. - https://github.com/aws/eks-pod-identity-agent/issues/14
- Work around `packedPolicySize` issue - https://github.com/aws/containers-roadmap/issues/2413

## How

In addition to normal [AssumeRoleForPodIdentity](https://docs.aws.amazon.com/eks/latest/APIReference/API_auth_AssumeRoleForPodIdentity.html) logic,
extensions adds following logic:
1. Get Namespace and Serviceaccount name from JWT token
1. Check them against `--chainrole-namespace-pattern` and `--chainrole-service-account-pattern` provided regexps
    - In case of no match, stop custom logic and proceed with normal flow
1. Call [DescribePodIdentityAssociation](https://docs.aws.amazon.com/eks/latest/APIReference/API_DescribePodIdentityAssociation.html) **using Pod Identity role** to get PodIdentityAssociation tags. ⚠️ See example permissions for Pod Identity role ⚠️

    ```json
      {
        "Sid" : "EKSDescribePodIdentities",
        "Effect" : "Allow",
        "Action" : "eks:DescribePodIdentityAssociation",
        "Resource" : "arn:aws:eks:*:123456789012:podidentityassociation/$${aws:PrincipalTag/eks-cluster-name}/*",
      }
    ```

1. Based on the tags with prefix `assume-role.ekspia.go.amzn.com` prepare parameters for [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) call 

    Example command to create Pod Identity Association with required tags:

    ```bash
    aws eks create-pod-identity-association --cluster-name my-test-cluster --namespace test-pod-identity  --service-account new-test-sa --role-arn arn:aws:iam::123456789012:role/my-pod-role --region us-west-2 --tags '{
        "assume-role.ekspia.go.amzn.com/role-arn": "arn:aws:iam::123456789012:role/my-new-role",
        "assume-role.ekspia.go.amzn.com/role-session-name": "my-session-name",
        "assume-role.ekspia.go.amzn.com/session-duration": "900s",
        "assume-role.ekspia.go.amzn.com/session-tag/tag1": "value1",
        "assume-role.ekspia.go.amzn.com/session-tag/tag2": "value2"
    }'
    ```

    See [`tagsToSTSAssumeRole` in chainrole.go](./pkg/extensions/chainrole/chainrole.go) to see list of supported params

1. [AssumeRole](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) **using EKS Pod Identity Agent's permissions**:
    - ⚠️ Role used by EKS Pod Identity Agent should have permissions to `sts:AssumeRole`, `sts:TagSession` and (optionally `sts:SetSourceIdentity`) for the target role configured in tags ⚠️
    - By default, EKS Pod Identity Agent uses Instance Profile Role - https://docs.aws.amazon.com/eks/latest/userguide/pod-id-agent-setup.html#pod-id-agent-add-on-create
    - For better security, you could assign IRSA role for EKS Pod Identity Agent and deny access to EC2 Instance metadata

1. Return credentials (where they will get cached and returned to requester)
