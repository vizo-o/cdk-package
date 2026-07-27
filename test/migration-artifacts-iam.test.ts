import { migrationArtifactsCicdPolicyStatements } from '../lib/constructs/migration-artifacts-iam'

describe('migrationArtifactsCicdPolicyStatements', () => {
    it('scopes object and list permissions to the app prefix', () => {
        const statements = migrationArtifactsCicdPolicyStatements({
            bucketArn: 'arn:aws:s3:::vizo-migration-artifacts-dev',
            appName: 'admin-system',
        })

        expect(statements).toHaveLength(2)

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
    })
})
