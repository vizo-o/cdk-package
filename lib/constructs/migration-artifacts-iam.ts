import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam'

export interface MigrationArtifactsCicdPolicyProps {
    bucketArn: string
    appName: string
}

/**
 * S3 permissions for CI/CD to upload migration Lambda zips under `{appName}/`.
 * Migration Lambda execution roles do not need these; UpdateFunctionCode uses the CICD role.
 */
export const migrationArtifactsCicdPolicyStatements = ({
    bucketArn,
    appName,
}: MigrationArtifactsCicdPolicyProps): PolicyStatement[] => {
    const prefix = `${appName}/`

    return [
        new PolicyStatement({
            effect: Effect.ALLOW,
            actions: ['s3:PutObject', 's3:GetObject', 's3:DeleteObject'],
            resources: [`${bucketArn}/${prefix}*`],
        }),
        new PolicyStatement({
            effect: Effect.ALLOW,
            actions: ['s3:ListBucket'],
            resources: [bucketArn],
            conditions: {
                StringLike: {
                    's3:prefix': [`${prefix}*`],
                },
            },
        }),
    ]
}
