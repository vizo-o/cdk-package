import { PolicyStatement } from 'aws-cdk-lib/aws-iam'

export type ApiGatewayHealthSmokeIamOptions = {
    region: string
    account: string
    restApiId: string
    stageName: string
    healthResourcePath?: string
}

const defaultHealthResourcePath = 'health/internal'

/**
 * CICD role may invoke GET /health/internal via SigV4 (post-deploy smoke, IAM auth).
 */
export const apiGatewayHealthSmokeInvokePolicyStatements = (
    options: ApiGatewayHealthSmokeIamOptions,
): PolicyStatement[] => {
    const path = options.healthResourcePath ?? defaultHealthResourcePath

    return [
        new PolicyStatement({
            actions: ['execute-api:Invoke'],
            resources: [
                `arn:aws:execute-api:${options.region}:${options.account}:${options.restApiId}/${options.stageName}/GET/${path}`,
            ],
        }),
    ]
}

export type ApiGatewayTestInvokePolicyOptions = {
    region: string
    restApiId: string
}

/**
 * Legacy test-invoke smoke (prefer IAM invoke via apiGatewayHealthSmokeInvokePolicyStatements).
 */
export const apiGatewayTestInvokePolicyStatements = (
    options: ApiGatewayTestInvokePolicyOptions,
): PolicyStatement[] => [
    new PolicyStatement({
        actions: [
            'apigateway:GET',
            'apigateway:POST',
            'apigateway:TestInvokeMethod',
        ],
        resources: [
            `arn:aws:apigateway:${options.region}::/restapis/${options.restApiId}/*`,
        ],
    }),
]
