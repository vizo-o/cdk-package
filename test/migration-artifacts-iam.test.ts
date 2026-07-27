import {
    MIGRATION_ARTIFACTS_BUCKET_NAME_SSM_PATH,
    migrationArtifactsCicdPolicyStatements,
} from '../lib/constructs/migration-artifacts-iam'

describe('migrationArtifactsCicdPolicyStatements', () => {
    it('scopes object, list, and SSM permissions for migration zip CI', () => {
        const statements = migrationArtifactsCicdPolicyStatements({
            bucketArn: 'arn:aws:s3:::vizo-migration-artifacts-dev',
            appName: 'admin-system',
            region: 'eu-central-1',
            account: '610896713610',
        })

        expect(statements).toHaveLength(3)

        const objectStmt = statements[0].toJSON()
        expect(objectStmt.Action).toEqual(
            expect.arrayContaining([
                's3:PutObject',
                's3:GetObject',
                's3:DeleteObject',
            ]),
        )
        expect(objectStmt.Resource).toBe(
            'arn:aws:s3:::vizo-migration-artifacts-dev/admin-system/*',
        )

        const listStmt = statements[1].toJSON()
        expect(listStmt.Action).toBe('s3:ListBucket')
        expect(listStmt.Resource).toBe(
            'arn:aws:s3:::vizo-migration-artifacts-dev',
        )
        expect(listStmt.Condition).toEqual({
            StringLike: { 's3:prefix': ['admin-system/*'] },
        })

        const ssmStmt = statements[2].toJSON()
        expect(ssmStmt.Action).toBe('ssm:GetParameter')
        expect(ssmStmt.Resource).toBe(
            `arn:aws:ssm:eu-central-1:610896713610:parameter${MIGRATION_ARTIFACTS_BUCKET_NAME_SSM_PATH}`,
        )
    })
})
