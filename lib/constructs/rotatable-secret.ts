import { Duration, RemovalPolicy } from 'aws-cdk-lib'
import * as iam from 'aws-cdk-lib/aws-iam'
import * as lambda from 'aws-cdk-lib/aws-lambda'
import { NodejsFunction } from 'aws-cdk-lib/aws-lambda-nodejs'
import * as logs from 'aws-cdk-lib/aws-logs'
import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager'
import { Construct } from 'constructs'
import * as path from 'path'

/**
 * Rotation strategy for secrets
 */
export enum RotationStrategy {
    /**
     * Dual-secret rotation: Both old and new secrets are valid during overlap period.
     * Used for secrets that sign/encrypt tokens (NextAuth, CognitoClientSecret).
     * Prevents invalidating active sessions.
     */
    DUAL_SECRET = 'DUAL_SECRET',

    /**
     * Immediate rotation: Old secret is immediately invalidated.
     * Used for secrets with short token expiration (JWT with 1-24h expiration).
     */
    IMMEDIATE = 'IMMEDIATE',
}

/**
 * Configuration for secret rotation
 */
export interface RotationConfig {
    /**
     * Rotation schedule interval (e.g., Duration.days(90))
     */
    scheduleInterval: Duration

    /**
     * Rotation strategy to use
     */
    strategy: RotationStrategy

    /**
     * For DUAL_SECRET strategy: How long both secrets should be valid (overlap period)
     * Should be at least as long as the longest possible session/token lifetime
     * Default: 30 days
     */
    overlapPeriod?: Duration

    /**
     * Secret generation configuration
     */
    generateSecretString?: secretsmanager.SecretStringGenerator
}

/**
 * Props for RotatableSecret construct
 */
export interface RotatableSecretProps {
    /**
     * Secret name (will be prefixed with appName/environment if provided)
     */
    secretName: string

    /**
     * Secret description
     */
    description: string

    /**
     * Rotation configuration
     */
    rotationConfig: RotationConfig

    /**
     * Optional app name for secret naming
     */
    appName?: string

    /**
     * Optional environment for secret naming
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
}

/**
 * A reusable construct for creating secrets with automatic rotation.
 * Supports both dual-secret rotation (for session secrets) and immediate rotation.
 *
 * @example
 * ```typescript
 * // NextAuth secret with dual-secret rotation
 * const nextAuthSecret = new RotatableSecret(this, 'NextAuthSecret', {
 *   secretName: 'nextauth-secret',
 *   description: 'NextAuth secret for session signing',
 *   appName: 'admin-system',
 *   environment: 'prod',
 *   rotationConfig: {
 *     scheduleInterval: Duration.days(90),
 *     strategy: RotationStrategy.DUAL_SECRET,
 *     overlapPeriod: Duration.days(30),
 *   },
 *   grantReadTo: [amplifyRole],
 * })
 * ```
 */
export class RotatableSecret extends Construct {
    public readonly secret: secretsmanager.Secret
    public readonly rotationLambda: lambda.Function

    constructor(
        scope: Construct,
        id: string,
        props: RotatableSecretProps,
    ) {
        super(scope, id)

        const {
            secretName,
            description,
            rotationConfig,
            appName,
            environment,
            removalPolicy = RemovalPolicy.RETAIN,
            grantReadTo = [],
        } = props

        // Build full secret name
        const fullSecretName = appName && environment
            ? `/${appName}/${environment}/${secretName}`
            : secretName

        // Create the secret
        this.secret = new secretsmanager.Secret(this, 'Secret', {
            secretName: fullSecretName,
            description,
            removalPolicy,
            generateSecretString:
                rotationConfig.generateSecretString || {
                    secretStringTemplate: JSON.stringify({}),
                    generateStringKey: 'current',
                    excludeCharacters: '"@/\\',
                    passwordLength: 64,
                },
        })

        // Create rotation Lambda function
        // Use the compiled JS file from the dist folder (TypeScript files aren't published)
        // NodejsFunction will bundle this JavaScript file
        const lambdaHandlerPath = path.join(
            path.dirname(require.resolve('@vizo-o/cdk-package/constructs')),
            'rotation-lambda',
            'index.js',
        )
        
        // Create log group with retention policy
        const logGroup = new logs.LogGroup(this, 'RotationLambdaLogGroup', {
            retention: logs.RetentionDays.ONE_MONTH,
            removalPolicy: RemovalPolicy.DESTROY,
        })
        
        this.rotationLambda = new NodejsFunction(this, 'RotationLambda', {
            runtime: lambda.Runtime.NODEJS_20_X,
            entry: lambdaHandlerPath,
            handler: 'handler',
            timeout: Duration.minutes(5),
            memorySize: 256,
            description: `Rotation function for ${description}`,
            logGroup,
            environment: {
                ROTATION_STRATEGY: rotationConfig.strategy,
                OVERLAP_PERIOD_DAYS: String(
                    (rotationConfig.overlapPeriod || Duration.days(30)).toDays(),
                ),
            },
        })

        // Grant Lambda permissions to read and update the secret
        this.secret.grantRead(this.rotationLambda)
        this.secret.grantWrite(this.rotationLambda)

        // Grant Lambda permission to describe the secret (needed for rotation)
        this.rotationLambda.addToRolePolicy(
            new iam.PolicyStatement({
                effect: iam.Effect.ALLOW,
                actions: ['secretsmanager:DescribeSecret'],
                resources: [this.secret.secretArn],
            }),
        )

        // Add rotation schedule
        this.secret.addRotationSchedule('RotationSchedule', {
            rotationLambda: this.rotationLambda,
            automaticallyAfter: rotationConfig.scheduleInterval,
        })

        // Grant read access to specified roles/users
        grantReadTo.forEach((grantable) => {
            this.secret.grantRead(grantable)
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
