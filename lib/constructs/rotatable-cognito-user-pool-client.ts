import { Duration, RemovalPolicy } from 'aws-cdk-lib'
import * as iam from 'aws-cdk-lib/aws-iam'
import * as lambda from 'aws-cdk-lib/aws-lambda'
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs'
import * as logs from 'aws-cdk-lib/aws-logs'
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager'
import { StringParameter } from 'aws-cdk-lib/aws-ssm'
import { Construct } from 'constructs'
import * as path from 'path'

/**
 * Configuration for Cognito User Pool Client rotation
 */
export interface CognitoClientRotationConfig {
    /**
     * Rotation schedule interval (e.g., Duration.days(90))
     */
    scheduleInterval: Duration

    /**
     * For DUAL_SECRET strategy: How long both secrets should be valid (overlap period)
     * Should be at least as long as the longest possible session/token lifetime
     * Default: 30 days
     */
    overlapPeriod?: Duration
}

/**
 * Props for RotatableCognitoUserPoolClient construct
 */
export interface RotatableCognitoUserPoolClientProps {
    /**
     * User Pool ID where the client will be created
     */
    userPoolId: string

    /**
     * User Pool ARN (for IAM permissions)
     */
    userPoolArn: string

    /**
     * Client name
     */
    clientName: string

    /**
     * Rotation configuration
     */
    rotationConfig: CognitoClientRotationConfig

    /**
     * Optional app name for secret naming and SSM parameters
     */
    appName?: string

    /**
     * Optional environment for secret naming and SSM parameters
     */
    environment?: string

    /**
     * Removal policy for the secret
     * @default RemovalPolicy.RETAIN
     */
    removalPolicy?: RemovalPolicy

    /**
     * Roles/users that should have read access to the secret
     */
    grantReadTo?: iam.IGrantable[]

    /**
     * OAuth callback URLs (will be set via post-deployment script)
     * These are stored in SSM for the rotation Lambda to use
     */
    callbackUrls?: string[]

    /**
     * OAuth logout URLs (will be set via post-deployment script)
     * These are stored in SSM for the rotation Lambda to use
     */
    logoutUrls?: string[]

    /**
     * Auth flows to enable
     */
    authFlows?: {
        userPassword?: boolean
        userSrp?: boolean
        adminUserPassword?: boolean
    }

    /**
     * OAuth scopes
     */
    oAuthScopes?: string[]

    /**
     * Refresh token validity (in days)
     */
    refreshTokenValidityDays?: number
}

/**
 * A reusable construct for managing Cognito User Pool Clients with automatic rotation.
 *
 * Creates a secret with rotation Lambda that rotates the Cognito User Pool Client
 * by creating a new client and updating the secret (dual-secret format for overlap period).
 *
 * The User Pool Client itself is NOT created by CDK - it must be created by a
 * post-deployment script that reads the configuration from SSM and creates the client.
 * 
 * @example
 * ```typescript
 * const rotatableClient = new RotatableCognitoUserPoolClient(this, 'CognitoClient', {
 *   userPoolId: userPool.userPoolId,
 *   userPoolArn: userPool.userPoolArn,
 *   clientName: 'my-app-client',
 *   appName: 'my-app',
 *   environment: 'prod',
 *   rotationConfig: {
 *     scheduleInterval: Duration.days(90),
 *     overlapPeriod: Duration.days(30),
 *   },
 *   grantReadTo: [lambdaRole],
 * })
 * ```
 */
export class RotatableCognitoUserPoolClient extends Construct {
    public readonly secret: secretsmanager.Secret
    public readonly rotationLambda: lambda.Function
    public readonly clientIdParameter: StringParameter
    public readonly clientSecretArnParameter: StringParameter

    constructor(
        scope: Construct,
        id: string,
        props: RotatableCognitoUserPoolClientProps,
    ) {
        super(scope, id)

        const {
            userPoolId,
            userPoolArn,
            clientName,
            rotationConfig,
            appName,
            environment,
            removalPolicy = RemovalPolicy.RETAIN,
            grantReadTo = [],
            callbackUrls = [],
            logoutUrls = [],
            authFlows = {
                userPassword: true,
                userSrp: true,
                adminUserPassword: true,
            },
            oAuthScopes = ['email', 'openid', 'profile'],
            refreshTokenValidityDays = 30,
        } = props

        const fullSecretName = appName && environment
            ? `/${appName}/${environment}/cognito-client-secret`
            : `cognito-client-secret`

        this.secret = new secretsmanager.Secret(this, 'ClientSecret', {
            secretName: fullSecretName,
            description: `Cognito User Pool Client Secret for ${clientName}`,
            removalPolicy,
            generateSecretString: {
                secretStringTemplate: JSON.stringify({}),
                generateStringKey: 'current',
                excludeCharacters: '"@/\\',
                passwordLength: 32,
            },
        })

        grantReadTo.forEach((grantable) => {
            this.secret.grantRead(grantable)
        })

        const configParameter = new StringParameter(
            this,
            'ClientConfigParameter',
            {
                parameterName: appName && environment
                    ? `/${appName}/${environment}/cognito/client-config`
                    : `/cognito/${clientName}/client-config`,
                stringValue: JSON.stringify({
                    userPoolId,
                    clientName,
                    callbackUrls,
                    logoutUrls,
                    authFlows,
                    oAuthScopes,
                    refreshTokenValidityDays,
                }),
                description: 'Cognito User Pool Client configuration',
            },
        )

        this.clientIdParameter = new StringParameter(this, 'ClientIdParameter', {
            parameterName: appName && environment
                ? `/${appName}/cognito/user-pool-client-id`
                : `/cognito/${clientName}/user-pool-client-id`,
            stringValue: 'PLACEHOLDER',
            description: 'Cognito User Pool Client ID',
        })

        this.clientSecretArnParameter = new StringParameter(
            this,
            'ClientSecretArnParameter',
            {
                parameterName: appName && environment
                    ? `/${appName}/cognito/client-secret-arn`
                    : `/cognito/${clientName}/client-secret-arn`,
                stringValue: this.secret.secretArn,
                description: 'ARN of Cognito Client Secret in Secrets Manager',
            },
        )

        const lambdaHandlerPath = path.join(
            path.dirname(require.resolve('@vizo-o/cdk-package/constructs')),
            'cognito-client-rotation-lambda',
            'index.js',
        )
        
        // Create log group with retention policy
        const logGroup = new logs.LogGroup(this, 'RotationLambdaLogGroup', {
            retention: logs.RetentionDays.ONE_MONTH,
            removalPolicy: RemovalPolicy.DESTROY,
        })
        
        this.rotationLambda = new NodejsFunction(
            this,
            'RotationLambda',
            {
                runtime: lambda.Runtime.NODEJS_20_X,
                entry: lambdaHandlerPath,
                handler: 'handler',
                timeout: Duration.minutes(5),
                memorySize: 512,
                description: `Rotation function for Cognito User Pool Client ${clientName}`,
                logGroup,
                environment: {
                    USER_POOL_ID: userPoolId,
                    CLIENT_NAME: clientName,
                    SECRET_ARN: this.secret.secretArn,
                    CLIENT_CONFIG_PARAMETER: configParameter.parameterName,
                    CLIENT_ID_PARAMETER: this.clientIdParameter.parameterName,
                    OVERLAP_PERIOD_DAYS: String(
                        (
                            rotationConfig.overlapPeriod ||
                            Duration.days(30)
                        ).toDays(),
                    ),
                },
            },
        )

        this.secret.grantRead(this.rotationLambda)
        this.secret.grantWrite(this.rotationLambda)

        this.rotationLambda.addToRolePolicy(
            new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: ['secretsmanager:DescribeSecret'],
                resources: [this.secret.secretArn],
            }),
        )

        this.rotationLambda.addToRolePolicy(
            new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: [
                    'cognito-idp:CreateUserPoolClient',
                    'cognito-idp:DeleteUserPoolClient',
                    'cognito-idp:DescribeUserPoolClient',
                    'cognito-idp:ListUserPoolClients',
                ],
                resources: [userPoolArn],
            }),
        )

        this.rotationLambda.addToRolePolicy(
            new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: ['ssm:GetParameter', 'ssm:PutParameter'],
                resources: [
                    configParameter.parameterArn,
                    this.clientIdParameter.parameterArn,
                ],
            }),
        )

        this.secret.addRotationSchedule('RotationSchedule', {
            rotationLambda: this.rotationLambda,
            automaticallyAfter: rotationConfig.scheduleInterval,
        })
    }

    /**
     * Get the secret ARN
     */
    public get secretArn(): string {
        return this.secret.secretArn
    }

    /**
     * Get the secret name
     */
    public get secretName(): string {
        return this.secret.secretName
    }
}
