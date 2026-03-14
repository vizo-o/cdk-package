# RotatableSecret Construct

A reusable CDK construct for creating AWS Secrets Manager secrets with automatic rotation support.

## Features

- **Dual-Secret Rotation**: Supports gradual rotation where both old and new secrets are valid during an overlap period (ideal for session secrets like NextAuth)
- **Immediate Rotation**: Supports immediate rotation where old secrets are invalidated immediately (ideal for short-lived tokens)
- **Automatic Scheduling**: Configurable rotation intervals
- **Reusable**: Can be used across multiple projects

## Usage

### NextAuth Secret (Dual-Secret Rotation)

```typescript
import { RotatableSecret, RotationStrategy } from '@vizo-o/cdk-package/constructs'
import { Duration } from 'aws-cdk-lib'

// In your CDK stack
const nextAuthSecret = new RotatableSecret(this, 'NextAuthSecret', {
    secretName: 'nextauth-secret',
    description: 'NextAuth secret for session signing',
    appName: 'admin-system',
    environment: 'prod',
    rotationConfig: {
        scheduleInterval: Duration.days(90), // Rotate every 90 days
        strategy: RotationStrategy.DUAL_SECRET,
        overlapPeriod: Duration.days(30), // Both secrets valid for 30 days
    },
    grantReadTo: [amplifyRole, computeRole],
})

// Use the secret
amplifyApp.addEnvironment('NEXTAUTH_SECRET_ARN', nextAuthSecret.secretArn)
```

### JWT Secret (Immediate Rotation)

```typescript
const jwtSecret = new RotatableSecret(this, 'JWTSecret', {
    secretName: 'jwt-secret',
    description: 'JWT secret for token signing',
    appName: 'onboarding',
    environment: 'prod',
    rotationConfig: {
        scheduleInterval: Duration.days(60), // Rotate every 60 days
        strategy: RotationStrategy.IMMEDIATE, // Immediate rotation
    },
    grantReadTo: [lambdaRole],
})
```

### Cognito Client Secret (Dual-Secret Rotation)

```typescript
const cognitoClientSecret = new RotatableSecret(this, 'CognitoClientSecret', {
    secretName: 'cognito-client-secret',
    description: 'Cognito User Pool Client Secret',
    appName: 'admin-system',
    environment: 'prod',
    rotationConfig: {
        scheduleInterval: Duration.days(90),
        strategy: RotationStrategy.DUAL_SECRET,
        overlapPeriod: Duration.days(30), // Match refresh token validity
    },
    grantReadTo: [amplifyRole, lambdaRole],
})
```

## Rotation Strategies

### DUAL_SECRET Strategy

- **Use Case**: Secrets that sign/encrypt tokens with long expiration (NextAuth sessions, Cognito refresh tokens)
- **Behavior**: 
  - During rotation, both old and new secrets are stored: `{ "current": "new-secret", "previous": "old-secret" }`
  - Both secrets remain valid during the overlap period
  - After overlap period, previous secret is removed
- **Overlap Period**: Should be at least as long as the longest possible session/token lifetime

### IMMEDIATE Strategy

- **Use Case**: Secrets with short token expiration (JWT tokens with 1-24h expiration)
- **Behavior**:
  - Old secret is immediately invalidated
  - Only new secret is stored: `{ "current": "new-secret" }`
  - Active tokens signed with old secret will fail validation

## Frontend Integration

For NextAuth.js, update your `auth-config.ts` to support dual-secret format:

```typescript
async function getSecretValue(secretArn: string): Promise<string> {
    const response = await secretsManagerClient.send(
        new GetSecretValueCommand({ SecretId: secretArn }),
    )
    
    if (!response.SecretString) {
        throw new Error('Secret string is empty')
    }

    // Support both single string and dual-secret format
    try {
        const parsed = JSON.parse(response.SecretString)
        if (parsed && typeof parsed === 'object' && 'current' in parsed) {
            // Dual-secret format - use current secret
            // NextAuth.js will automatically handle both secrets during rotation
            return parsed.current
        }
    } catch {
        // Not JSON, return as-is
    }

    return response.SecretString
}
```

**Note**: NextAuth.js v4+ automatically supports multiple secrets for session validation, so tokens signed with either secret will work during the overlap period.

## Best Practices

1. **Rotation Schedule**: 
   - Session secrets: 90 days
   - Short-lived tokens: 60 days
   - Critical secrets: 30-60 days

2. **Overlap Period**:
   - Should match or exceed the longest possible session/token lifetime
   - NextAuth: 30 days (matches default session duration)
   - Cognito: 30 days (matches refresh token validity)

3. **Monitoring**:
   - Set up CloudWatch alarms for rotation failures
   - Monitor authentication errors during rotation windows
   - Log rotation events for audit purposes

4. **Testing**:
   - Test rotation in dev environment first
   - Verify dual-secret behavior works correctly
   - Ensure no user disruption during rotation
