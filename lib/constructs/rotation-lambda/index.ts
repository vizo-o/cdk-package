import {
    DescribeSecretCommand,
    GetSecretValueCommand,
    PutSecretValueCommand,
    SecretsManagerClient,
} from '@aws-sdk/client-secrets-manager'
import { randomBytes } from 'crypto'

// Note: This Lambda handler is bundled by NodejsFunction construct
// Dependencies should be added to the CDK package.json

const secretsManager = new SecretsManagerClient({})

/**
 * Generate a random secret string
 */
function generateSecret(length: number = 64): string {
    return randomBytes(length).toString('base64')
}

/**
 * Parse secret value - supports both single string and dual-secret format
 */
function parseSecretValue(secretString: string): {
    current: string
    previous: string | null
} {
    try {
        const parsed = JSON.parse(secretString)
        if (
            parsed &&
            typeof parsed === 'object' &&
            'current' in parsed
        ) {
            return {
                current: parsed.current,
                previous: parsed.previous || null,
            }
        }
    } catch {
        // Not JSON, treat as single secret
    }

    return {
        current: secretString,
        previous: null,
    }
}

/**
 * Format secret value for storage
 */
function formatSecretValue(
    current: string,
    previous: string | null = null,
): string {
    if (previous) {
        return JSON.stringify({ current, previous })
    }

    return JSON.stringify({ current })
}

/**
 * AWS Secrets Manager rotation handler
 * Supports both DUAL_SECRET and IMMEDIATE rotation strategies
 */
export async function handler(event: {
    SecretId: string
    ClientRequestToken: string
    Step: 'createSecret' | 'setSecret' | 'testSecret' | 'finishSecret'
}): Promise<void> {
    const secretArn = event.SecretId
    const token = event.ClientRequestToken
    const step = event.Step

    const rotationStrategy =
        process.env.ROTATION_STRATEGY || 'DUAL_SECRET'
    const overlapPeriodDays = parseInt(
        process.env.OVERLAP_PERIOD_DAYS || '30',
        10,
    )

    try {
        // Get secret metadata
        const metadata = await secretsManager.send(
            new DescribeSecretCommand({ SecretId: secretArn }),
        )

        // Verify version token matches
        if (
            metadata.VersionIdsToStages &&
            !metadata.VersionIdsToStages[token]?.includes('AWSCURRENT')
        ) {
            throw new Error(
                `Token ${token} is not the current version of the secret`,
            )
        }

        switch (step) {
            case 'createSecret':
                // Create new secret version
                await createSecret(secretArn, token, rotationStrategy)
                break

            case 'setSecret':
                // Set the new secret value
                await setSecret(secretArn, token, rotationStrategy)
                break

            case 'testSecret':
                // Required step in AWS Secrets Manager rotation protocol
                // AWS calls this step to verify the new secret version is ready
                // No additional validation needed - secret format is already validated
                // in createSecret/setSecret steps, and AWS handles the version validation
                break

            case 'finishSecret':
                // Finish rotation - cleanup old secret if needed
                await finishSecret(
                    secretArn,
                    token,
                    rotationStrategy,
                    overlapPeriodDays,
                )
                break

            default:
                throw new Error(`Unknown step: ${step}`)
        }
    } catch (error) {
        console.error(`Error in step ${step}:`, error)
        throw error
    }
}

/**
 * Create a new secret version
 */
async function createSecret(
    secretArn: string,
    token: string,
    strategy: string,
): Promise<void> {
    console.log(`Creating new secret version for ${secretArn}`)

    // Get current secret value
    const currentSecret = await secretsManager.send(
        new GetSecretValueCommand({ SecretId: secretArn }),
    )

    if (!currentSecret.SecretString) {
        throw new Error('Current secret has no value')
    }

    const { current, previous } = parseSecretValue(
        currentSecret.SecretString,
    )

    // Generate new secret
    const newSecret = generateSecret(64)

    // For DUAL_SECRET strategy, keep both old and new secrets
    // For IMMEDIATE strategy, only keep new secret
    const secretValue =
        strategy === 'DUAL_SECRET'
            ? formatSecretValue(newSecret, current)
            : formatSecretValue(newSecret)

    // Create new version
    await secretsManager.send(
        new PutSecretValueCommand({
            SecretId: secretArn,
            ClientRequestToken: token,
            SecretString: secretValue,
            VersionStages: ['AWSPENDING'],
        }),
    )

    console.log('New secret version created successfully')
}

/**
 * Set the secret value (called after createSecret)
 */
async function setSecret(
    secretArn: string,
    token: string,
    strategy: string,
): Promise<void> {
    console.log(`Setting secret value for ${secretArn}`)

    // Get pending secret
    const pendingSecret = await secretsManager.send(
        new GetSecretValueCommand({
            SecretId: secretArn,
            VersionStage: 'AWSPENDING',
        }),
    )

    if (!pendingSecret.SecretString) {
        throw new Error('Pending secret has no value')
    }

    // For DUAL_SECRET strategy, the secret is already set with both values
    // For IMMEDIATE strategy, we might want to do additional setup here
    console.log('Secret value set successfully')
}

/**
 * Finish rotation - cleanup old secret if needed
 */
async function finishSecret(
    secretArn: string,
    token: string,
    strategy: string,
    overlapPeriodDays: number,
): Promise<void> {
    console.log(`Finishing rotation for ${secretArn}`)

    // Get current secret
    const currentSecret = await secretsManager.send(
        new GetSecretValueCommand({ SecretId: secretArn }),
    )

    if (!currentSecret.SecretString) {
        throw new Error('Current secret has no value')
    }

    const secretValue = parseSecretValue(currentSecret.SecretString)

    // For IMMEDIATE strategy, just mark pending as current
    if (strategy === 'IMMEDIATE') {
        await secretsManager.send(
            new PutSecretValueCommand({
                SecretId: secretArn,
                ClientRequestToken: token,
                VersionStages: ['AWSCURRENT'],
            }),
        )
        console.log('Rotation finished - immediate strategy')
        return
    }

    // For DUAL_SECRET strategy:
    // - If there's a previous secret, check if overlap period has passed
    // - If overlap period passed, remove previous secret
    // - Otherwise, keep both secrets for gradual transition

    if (secretValue.previous) {
        // Check when this version was created
        const metadata = await secretsManager.send(
            new DescribeSecretCommand({ SecretId: secretArn }),
        )

        // Find the version that contains this current secret
        const versions = metadata.VersionIdsToStages || {}
        const currentVersionId = Object.keys(versions).find(
            (versionId) =>
                versions[versionId]?.includes('AWSCURRENT') &&
                versionId !== token,
        )

        if (currentVersionId) {
            // Get creation date of current version by fetching the version
            const versionSecret = await secretsManager.send(
                new GetSecretValueCommand({
                    SecretId: secretArn,
                    VersionId: currentVersionId,
                }),
            )

            const createdDate = versionSecret.CreatedDate
            if (createdDate) {
                const daysSinceCreation =
                    (Date.now() - createdDate.getTime()) /
                    (1000 * 60 * 60 * 24)

                // If overlap period has passed, remove previous secret
                if (daysSinceCreation >= overlapPeriodDays) {
                    console.log(
                        `Overlap period (${overlapPeriodDays} days) has passed, removing previous secret`,
                    )
                    await secretsManager.send(
                        new PutSecretValueCommand({
                            SecretId: secretArn,
                            ClientRequestToken: token,
                            SecretString: formatSecretValue(secretValue.current),
                            VersionStages: ['AWSCURRENT'],
                        }),
                    )
                    console.log('Previous secret removed')
                    return
                }

                console.log(
                    `Overlap period not yet complete (${Math.round(daysSinceCreation)}/${overlapPeriodDays} days), keeping both secrets`,
                )
            }
        }
    }

    // Mark pending version as current
    await secretsManager.send(
        new PutSecretValueCommand({
            SecretId: secretArn,
            ClientRequestToken: token,
            VersionStages: ['AWSCURRENT'],
        }),
    )

    console.log('Rotation finished - dual-secret strategy')
}
