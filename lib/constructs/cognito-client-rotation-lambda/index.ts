import {
    CognitoIdentityProviderClient,
    CreateUserPoolClientCommand,
    DeleteUserPoolClientCommand,
    DescribeUserPoolClientCommand,
    ListUserPoolClientsCommand,
} from '@aws-sdk/client-cognito-identity-provider'
import {
    GetSecretValueCommand,
    PutSecretValueCommand,
    SecretsManagerClient
} from '@aws-sdk/client-secrets-manager'
import {
    GetParameterCommand,
    PutParameterCommand,
    SSMClient,
} from '@aws-sdk/client-ssm'

const cognitoClient = new CognitoIdentityProviderClient({})
const secretsManager = new SecretsManagerClient({})
const ssmClient = new SSMClient({})

/**
 * Parse secret value - supports dual-secret format
 */
function parseSecretValue(secretString: string): {
    current: string
    previous: string | null
    oldClientId?: string
    newClientId?: string
} {
    try {
        const parsed = JSON.parse(secretString)
        if (parsed && typeof parsed === 'object' && 'current' in parsed) {
            return {
                current: parsed.current,
                previous: parsed.previous || null,
                oldClientId: parsed.oldClientId,
                newClientId: parsed.newClientId,
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
 * AWS Secrets Manager rotation handler for Cognito User Pool Client
 *
 * This Lambda rotates the Cognito User Pool Client by:
 * 1. Creating a new User Pool Client with the same configuration
 * 2. Updating the secret in Secrets Manager with the new secret (dual-secret format)
 * 3. After overlap period, deleting the old client and removing previous secret
 */
export async function handler(event: {
    SecretId: string
    ClientRequestToken: string
    Step: 'createSecret' | 'setSecret' | 'testSecret' | 'finishSecret'
}): Promise<void> {
    const secretArn = event.SecretId
    const token = event.ClientRequestToken
    const step = event.Step

    const userPoolId = process.env.USER_POOL_ID!
    const clientName = process.env.CLIENT_NAME!
    const clientConfigParameter = process.env.CLIENT_CONFIG_PARAMETER!
    const clientIdParameter = process.env.CLIENT_ID_PARAMETER!
    const overlapPeriodDays = parseInt(
        process.env.OVERLAP_PERIOD_DAYS || '30',
        10,
    )

    try {
        switch (step) {
            case 'createSecret':
                await createSecret(
                    secretArn,
                    token,
                    userPoolId,
                    clientName,
                    clientConfigParameter,
                    clientIdParameter,
                )
                break

            case 'setSecret':
                console.log('Secret value set successfully')
                break

            case 'testSecret':
                await testSecret(secretArn, token, clientIdParameter, userPoolId)
                break

            case 'finishSecret':
                await finishSecret(
                    secretArn,
                    token,
                    overlapPeriodDays,
                    userPoolId,
                    clientName,
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
 * Create a new Cognito User Pool Client and update the secret
 */
async function createSecret(
    secretArn: string,
    token: string,
    userPoolId: string,
    clientName: string,
    clientConfigParameter: string,
    clientIdParameter: string,
): Promise<void> {
    console.log(`Creating new Cognito User Pool Client for ${clientName}`)

    // Get current secret value
    const currentSecret = await secretsManager.send(
        new GetSecretValueCommand({ SecretId: secretArn }),
    )

    if (!currentSecret.SecretString) {
        throw new Error('Current secret has no value')
    }

    const { current: currentSecretValue } = parseSecretValue(
        currentSecret.SecretString,
    )

    const configResponse = await ssmClient.send(
        new GetParameterCommand({ Name: clientConfigParameter }),
    )

    if (!configResponse.Parameter?.Value) {
        throw new Error('Client configuration not found in SSM')
    }

    const config = JSON.parse(configResponse.Parameter.Value)

    const clientIdResponse = await ssmClient.send(
        new GetParameterCommand({ Name: clientIdParameter }),
    )

    if (!clientIdResponse.Parameter?.Value) {
        throw new Error('Client ID not found in SSM')
    }

    const currentClientId = clientIdResponse.Parameter.Value

    const currentClientResponse = await cognitoClient.send(
        new DescribeUserPoolClientCommand({
            UserPoolId: userPoolId,
            ClientId: currentClientId,
        }),
    )

    const currentClient = currentClientResponse.UserPoolClient
    if (!currentClient) {
        throw new Error('Current User Pool Client not found')
    }

    const newClientResponse = await cognitoClient.send(
        new CreateUserPoolClientCommand({
            UserPoolId: userPoolId,
            ClientName: clientName,
            GenerateSecret: true,
            ExplicitAuthFlows: currentClient.ExplicitAuthFlows || [
                'ALLOW_USER_PASSWORD_AUTH',
                'ALLOW_USER_SRP_AUTH',
                'ALLOW_ADMIN_USER_PASSWORD_AUTH',
                'ALLOW_REFRESH_TOKEN_AUTH',
            ],
            SupportedIdentityProviders:
                currentClient.SupportedIdentityProviders || ['COGNITO'],
            CallbackURLs: currentClient.CallbackURLs || config.callbackUrls,
            LogoutURLs: currentClient.LogoutURLs || config.logoutUrls,
            AllowedOAuthFlows: currentClient.AllowedOAuthFlows || ['code'],
            AllowedOAuthScopes:
                currentClient.AllowedOAuthScopes || config.oAuthScopes,
            AllowedOAuthFlowsUserPoolClient:
                currentClient.AllowedOAuthFlowsUserPoolClient || true,
            RefreshTokenValidity: currentClient.RefreshTokenValidity || 30,
            AccessTokenValidity: currentClient.AccessTokenValidity,
            IdTokenValidity: currentClient.IdTokenValidity,
            TokenValidityUnits: currentClient.TokenValidityUnits,
            ReadAttributes: currentClient.ReadAttributes,
            WriteAttributes: currentClient.WriteAttributes,
            EnableTokenRevocation:
                currentClient.EnableTokenRevocation || false,
            PreventUserExistenceErrors:
                currentClient.PreventUserExistenceErrors || 'LEGACY',
        }),
    )

    const newClient = newClientResponse.UserPoolClient
    if (!newClient || !newClient.ClientSecret) {
        throw new Error('Failed to create new User Pool Client')
    }

    const newClientSecret = newClient.ClientSecret
    const newClientId = newClient.ClientId!

    const secretValue = JSON.stringify({
        current: newClientSecret,
        previous: currentSecretValue,
        oldClientId: currentClientId,
        newClientId: newClientId,
    })

    await secretsManager.send(
        new PutSecretValueCommand({
            SecretId: secretArn,
            ClientRequestToken: token,
            SecretString: secretValue,
            VersionStages: ['AWSPENDING'],
        }),
    )

    console.log('New Cognito User Pool Client created successfully')
    console.log(`New Client ID: ${newClientId}`)
    console.log(`Old Client ID: ${currentClientId}`)
}

/**
 * Test that the new secret works and update client ID in SSM
 */
async function testSecret(
    secretArn: string,
    token: string,
    clientIdParameter: string,
    userPoolId: string,
): Promise<void> {
    console.log('Testing new secret...')

    const pendingSecret = await secretsManager.send(
        new GetSecretValueCommand({
            SecretId: secretArn,
            VersionStage: 'AWSPENDING',
        }),
    )

    if (!pendingSecret.SecretString) {
        throw new Error('Pending secret has no value')
    }

    const secretData = parseSecretValue(pendingSecret.SecretString)
    const newClientId = secretData.newClientId

    if (!newClientId) {
        throw new Error('New client ID not found in secret metadata')
    }

    await cognitoClient.send(
        new DescribeUserPoolClientCommand({
            UserPoolId: userPoolId,
            ClientId: newClientId,
        }),
    )

    await ssmClient.send(
        new PutParameterCommand({
            Name: clientIdParameter,
            Value: newClientId,
            Overwrite: true,
            Type: 'String',
        }),
    )

    console.log(`Secret test passed - new client ${newClientId} is accessible`)
    console.log(`Updated client ID in SSM parameter: ${clientIdParameter}`)
}

/**
 * Check if overlap period has expired for this rotation
 */
function isOverlapPeriodExpired(
    rotationStartDate: Date | undefined,
    overlapPeriodDays: number,
): boolean {
    if (!rotationStartDate) {
        return false
    }

    const daysSinceRotation =
        (Date.now() - rotationStartDate.getTime()) / (1000 * 60 * 60 * 24)

    return daysSinceRotation >= overlapPeriodDays
}

/**
 * List all Cognito clients with the given name
 */
async function listClientsByName(
    userPoolId: string,
    clientName: string,
): Promise<string[]> {
    const allClients: string[] = []
    let nextToken: string | undefined

    do {
        const listResponse = await cognitoClient.send(
            new ListUserPoolClientsCommand({
                UserPoolId: userPoolId,
                MaxResults: 60,
                NextToken: nextToken,
            }),
        )

        const clients = listResponse.UserPoolClients || []
        for (const client of clients) {
            if (client.ClientName === clientName && client.ClientId) {
                allClients.push(client.ClientId)
            }
        }

        nextToken = listResponse.NextToken
    } while (nextToken)

    return allClients
}

/**
 * Collect all client IDs referenced in secret metadata
 */
function getReferencedClientIds(
    currentSecretData: ReturnType<typeof parseSecretValue>,
    pendingSecretData: ReturnType<typeof parseSecretValue>,
): Set<string> {
    const referenced = new Set<string>()

    // Current client (new one from pending secret)
    if (pendingSecretData.newClientId) {
        referenced.add(pendingSecretData.newClientId)
    }

    // Old client from this rotation (from pending secret)
    if (
        pendingSecretData.oldClientId &&
        pendingSecretData.oldClientId !== pendingSecretData.newClientId
    ) {
        referenced.add(pendingSecretData.oldClientId)
    }

    // Clients from previous rotation (from current secret)
    if (
        currentSecretData.oldClientId &&
        currentSecretData.oldClientId !== pendingSecretData.newClientId
    ) {
        referenced.add(currentSecretData.oldClientId)
    }
    if (
        currentSecretData.newClientId &&
        currentSecretData.newClientId !== pendingSecretData.newClientId
    ) {
        referenced.add(currentSecretData.newClientId)
    }

    return referenced
}

/**
 * Determine which clients should be kept (not deleted)
 */
function getClientsToKeep(
    currentClientId: string,
    oldClientId: string | undefined,
    referencedClientIds: Set<string>,
    overlapPeriodExpired: boolean,
): Set<string> {
    const toKeep = new Set<string>()

    // Always keep current client
    toKeep.add(currentClientId)

    // Keep old client if overlap period hasn't expired
    if (oldClientId && !overlapPeriodExpired && oldClientId !== currentClientId) {
        toKeep.add(oldClientId)
    }

    // During overlap period, keep all referenced clients (they might be from previous rotations)
    if (!overlapPeriodExpired) {
        referencedClientIds.forEach((id) => toKeep.add(id))
    }

    return toKeep
}

/**
 * Delete a Cognito client, handling errors gracefully
 */
async function deleteClientSafely(
    userPoolId: string,
    clientId: string,
    description: string,
): Promise<void> {
    try {
        console.log(`Deleting ${description}: ${clientId}`)
        await cognitoClient.send(
            new DeleteUserPoolClientCommand({
                UserPoolId: userPoolId,
                ClientId: clientId,
            }),
        )
        console.log(`Successfully deleted ${description}: ${clientId}`)
    } catch (error) {
        if (
            error instanceof Error &&
            error.message.includes('does not exist')
        ) {
            console.log(`${description} ${clientId} already deleted, continuing...`)
        } else {
            console.error(`Failed to delete ${description} ${clientId}:`, error)
            throw error
        }
    }
}

/**
 * Update secret to AWSCURRENT stage
 */
async function updateSecretToCurrent(
    secretArn: string,
    token: string,
    secretValue: string,
): Promise<void> {
    await secretsManager.send(
        new PutSecretValueCommand({
            SecretId: secretArn,
            ClientRequestToken: token,
            SecretString: secretValue,
            VersionStages: ['AWSCURRENT'],
        }),
    )
}

/**
 * Finish rotation - cleanup old client after overlap period
 * Also cleans up any orphaned clients that aren't referenced in the secret
 */
async function finishSecret(
    secretArn: string,
    token: string,
    overlapPeriodDays: number,
    userPoolId: string,
    clientName: string,
): Promise<void> {
    console.log('Finishing rotation...')

    // Get current and pending secrets
    const [currentSecret, pendingSecret] = await Promise.all([
        secretsManager.send(
            new GetSecretValueCommand({ SecretId: secretArn }),
        ),
        secretsManager.send(
            new GetSecretValueCommand({
                SecretId: secretArn,
                VersionStage: 'AWSPENDING',
            }),
        ),
    ])

    if (!currentSecret.SecretString || !pendingSecret.SecretString) {
        throw new Error('Secret has no value')
    }

    const currentSecretData = parseSecretValue(currentSecret.SecretString)
    const pendingSecretData = parseSecretValue(pendingSecret.SecretString)

    const currentClientId = pendingSecretData.newClientId
    const oldClientId = pendingSecretData.oldClientId

    if (!currentClientId) {
        await updateSecretToCurrent(
            secretArn,
            token,
            pendingSecret.SecretString,
        )
        console.log('Rotation finished - no client ID found in secret')
        return
    }

    // Check if overlap period has expired
    const overlapExpired = isOverlapPeriodExpired(
        pendingSecret.CreatedDate,
        overlapPeriodDays,
    )

    if (overlapExpired) {
        console.log(
            `Overlap period (${overlapPeriodDays} days) has passed, deleting old client`,
        )
    } else {
        const daysSinceRotation = pendingSecret.CreatedDate
            ? Math.round(
                  (Date.now() - pendingSecret.CreatedDate.getTime()) /
                      (1000 * 60 * 60 * 24),
              )
            : 0
        console.log(
            `Overlap period not yet complete (${daysSinceRotation}/${overlapPeriodDays} days), keeping both clients`,
        )
    }

    // List all clients and determine which to keep
    const allClients = await listClientsByName(userPoolId, clientName)
    console.log(
        `Found ${allClients.length} clients with name "${clientName}": ${allClients.join(', ')}`,
    )

    const referencedClientIds = getReferencedClientIds(
        currentSecretData,
        pendingSecretData,
    )

    const clientsToKeep = getClientsToKeep(
        currentClientId,
        oldClientId,
        referencedClientIds,
        overlapExpired,
    )

    // Log which clients we're keeping
    if (oldClientId && !overlapExpired && oldClientId !== currentClientId) {
        console.log(`Keeping old client ${oldClientId} (within overlap period)`)
    }

    // Find and delete orphaned clients
    const orphanedClients = allClients.filter(
        (clientId) => !clientsToKeep.has(clientId),
    )

    if (orphanedClients.length > 0) {
        console.log(
            `Found ${orphanedClients.length} orphaned clients to delete: ${orphanedClients.join(', ')}`,
        )

        for (const orphanedClientId of orphanedClients) {
            await deleteClientSafely(
                userPoolId,
                orphanedClientId,
                'orphaned client',
            ).catch((error) => {
                // Log but continue - don't fail rotation if orphan cleanup fails
                console.error(
                    `Failed to delete orphaned client ${orphanedClientId}:`,
                    error,
                )
            })
        }
    }

    // Delete old client if overlap period expired
    if (overlapExpired && oldClientId && oldClientId !== currentClientId) {
        await deleteClientSafely(userPoolId, oldClientId, 'old client').catch(
            (error) => {
                // Log but continue - don't fail rotation if deletion fails
                console.error('Failed to delete old client:', error)
            },
        )
    }

    // Update secret to AWSCURRENT
    const finalSecretValue = overlapExpired
        ? JSON.stringify({
              current: pendingSecretData.current,
              newClientId: pendingSecretData.newClientId,
          })
        : JSON.stringify({
              current: pendingSecretData.current,
              previous: pendingSecretData.previous,
              oldClientId: pendingSecretData.oldClientId,
              newClientId: pendingSecretData.newClientId,
          })

    await updateSecretToCurrent(secretArn, token, finalSecretValue)

    console.log('Rotation finished successfully')
}
