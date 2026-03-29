import type { IManagedPolicy, IPrincipal } from 'aws-cdk-lib/aws-iam'
import {
    ArnPrincipal,
    CompositePrincipal,
    Effect,
    ManagedPolicy,
    PolicyDocument,
    PolicyStatement,
    Role,
    WebIdentityPrincipal,
} from 'aws-cdk-lib/aws-iam'
import { Fn, Stack } from 'aws-cdk-lib/core'
import { Construct } from 'constructs'

const kebabToPascal = (kebab: string) => {
    const words = kebab.split('-')

    return words.map((word) => word[0].toUpperCase() + word.slice(1)).join('')
}

interface CICDRoleProps {
    repoName: string
    inlinePolicies?: { [name: string]: PolicyDocument }
    managedPolicies?: IManagedPolicy[]
}

export class CICDRole extends Construct {
    role: Role

    constructor(
        scope: Construct,
        id: string,
        { repoName, managedPolicies, inlinePolicies }: CICDRoleProps,
    ) {
        super(scope, id)

        const baseCICDRoleManagedPolicyArn = Fn.importValue('BaseCICDPolicyArn')

        const githubDomain = 'token.actions.githubusercontent.com'
        const stsClientId = 'sts.amazonaws.com'

        const githubProviderArn = `arn:aws:iam::${
            Stack.of(this).account
        }:oidc-provider/${githubDomain}`

        const githubActionsPrincipal = new WebIdentityPrincipal(
            githubProviderArn,
            {
                StringLike: {
                    [`${githubDomain}:sub`]: [`repo:vizo-o/${repoName}:*`],
                },
                StringEquals: {
                    'token.actions.githubusercontent.com:aud': stsClientId,
                },
            },
        )

        let assumedBy: IPrincipal = githubActionsPrincipal

        if (process.env?.ENV === 'dev') {
            const devPrincipal = new ArnPrincipal(
                `arn:aws:iam::${
                    Stack.of(this).account
                }:role/aws-reserved/sso.amazonaws.com/${
                    Stack.of(this).region
                    // the following is the ID of the AWSReservedSSO_AdministratorAccess role
                    // from the managing aws account
                }/AWSReservedSSO_AdministratorAccess_b67729ec493a65d3`,
            )

            assumedBy = new CompositePrincipal(
                githubActionsPrincipal,
                devPrincipal,
            )
        }

        const isProd = process.env?.ENV !== 'dev'
        const sesPolicy: PolicyDocument | undefined = isProd
            ? new PolicyDocument({
                  statements: [
                      new PolicyStatement({
                          effect: Effect.ALLOW,
                          actions: ['ses:SendEmail', 'ses:SendRawEmail'],
                          resources: ['*'],
                      }),
                  ],
              })
            : undefined

        this.role = new Role(this, 'DeployRole', {
            assumedBy: assumedBy,
            roleName: `${kebabToPascal(repoName)}CICDRole`,
            managedPolicies: [
                ManagedPolicy.fromManagedPolicyArn(
                    this,
                    'BaseCICDRoleManagedPolicy',
                    baseCICDRoleManagedPolicyArn,
                ),
                ...(managedPolicies ?? []),
            ],
            inlinePolicies: {
                ...(sesPolicy ? { CICDSesNotificationPolicy: sesPolicy } : {}),
                ...(inlinePolicies ?? {}),
            },
        })
    }
}
