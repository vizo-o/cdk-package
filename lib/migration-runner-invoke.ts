import { PolicyStatement } from 'aws-cdk-lib/aws-iam'

export type MigrationRunnerInvokePayload = {
    source: 'cicd-migrate'
    repoName: string
    runId: string
    gitSha?: string
    githubOwner?: string
    githubRepo?: string
    artifactName?: string
}

export interface MigrationRunnerCicdPolicyProps {
    migrationRunnerFunctionArn: string
}

/** CICD: invoke shared infra-db migration runner (no UpdateFunctionCode). */
export const migrationRunnerCicdInvokePolicyStatements = ({
    migrationRunnerFunctionArn,
}: MigrationRunnerCicdPolicyProps): PolicyStatement[] => [
    new PolicyStatement({
        actions: ['lambda:GetFunction', 'lambda:InvokeFunction'],
        resources: [migrationRunnerFunctionArn],
    }),
]
