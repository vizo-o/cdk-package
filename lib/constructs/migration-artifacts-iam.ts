import { Effect, PolicyStatement } from 'aws-cdk-lib/aws-iam'

/** SSM path written by infra-base MigrationArtifacts construct. */
export const MIGRATION_ARTIFACTS_BUCKET_NAME_SSM_PATH =
    '/infra-base/migration-artifacts-bucket-name'

export interface MigrationArtifactsCicdPolicyProps {
    bucketArn: string
    appName: string
    region: string
    account: string
}

/**
 * IAM for CI/CD migration zip publish, deploy resolve, and S3 cleanup:
 * S3 under `{appName}/`, plus SSM read for the shared artifacts bucket name.
 * Migration Lambda execution roles do not need these.
 */
export const migrationArtifactsCicdPolicyStatements = ({
    bucketArn,
    appName,
    region,
    account,
}: MigrationArtifactsCicdPolicyProps): PolicyStatement[] => {
    const prefix = `${appName}/`
    const bucketNameParamArn = `arn:aws:ssm:${region}:${account}:parameter${MIGRATION_ARTIFACTS_BUCKET_NAME_SSM_PATH}`

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
        new PolicyStatement({
            effect: Effect.ALLOW,
            actions: ['ssm:GetParameter'],
            resources: [bucketNameParamArn],
        }),
    ]
}
