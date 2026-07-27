import {
    apiGatewayHealthSmokeInvokePolicyStatements,
    apiGatewayTestInvokePolicyStatements,
} from '../lib/api-gateway-health-smoke-iam'

describe('apiGatewayHealthSmokeInvokePolicyStatements', () => {
    it('scopes execute-api:Invoke to GET health/internal', () => {
        const [statement] = apiGatewayHealthSmokeInvokePolicyStatements({
            region: 'eu-central-1',
            account: '123456789012',
            restApiId: 'abc123',
            stageName: 'prod',
        })

        expect(statement.toStatementJson()).toMatchObject({
            Action: 'execute-api:Invoke',
            Resource:
                'arn:aws:execute-api:eu-central-1:123456789012:abc123/prod/GET/health/internal',
        })
    })
})

describe('apiGatewayTestInvokePolicyStatements', () => {
    it('grants apigateway test-invoke on the REST API', () => {
        const [statement] = apiGatewayTestInvokePolicyStatements({
            region: 'eu-central-1',
            restApiId: 'abc123',
        })

        expect(statement.toStatementJson().Action).toEqual(
            expect.arrayContaining(['apigateway:TestInvokeMethod']),
        )
    })
})
