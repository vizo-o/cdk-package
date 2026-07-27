import { migrationRunnerCicdInvokePolicyStatements } from '../lib/migration-runner-invoke'

describe('migrationRunnerCicdInvokePolicyStatements', () => {
    it('grants invoke on the shared migration runner only', () => {
        const arn =
            'arn:aws:lambda:eu-central-1:610896713610:function:infra-db-migration-runner'
        const statements = migrationRunnerCicdInvokePolicyStatements({
            migrationRunnerFunctionArn: arn,
        })
        expect(statements).toHaveLength(1)
        expect(statements[0].toStatementJson()).toMatchObject({
            Action: ['lambda:GetFunction', 'lambda:InvokeFunction'],
            Resource: arn,
        })
    })
})
