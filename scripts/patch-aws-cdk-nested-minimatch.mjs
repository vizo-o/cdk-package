#!/usr/bin/env node
/**
 * Install-time patch: align aws-cdk-lib’s nested `minimatch` with the root install.
 *
 * What it does
 * ------------
 * After `npm install`, npm may place a separate copy of `minimatch` under
 * `node_modules/aws-cdk-lib/node_modules/minimatch`. That nested copy can stay on a
 * vulnerable version even when the package.json `overrides` / top-level
 * `node_modules/minimatch` pin a patched release (different dependency path).
 *
 * This script deletes that nested folder (if present) and replaces it with a
 * recursive copy of the root `node_modules/minimatch` tree, so anything resolving
 * `minimatch` from inside `aws-cdk-lib` gets the same bits as the hoisted package.
 *
 * Why it exists
 * -------------
 * Primarily to satisfy `npm audit --audit-level=high` and real runtime use of the
 * patched glob/minimatch stack without waiting on upstream to flatten the tree.
 *
 * When it runs
 * ------------
 * Only when both paths exist:
 * - `<packageRoot>/node_modules/aws-cdk-lib/node_modules/minimatch`
 * - `<packageRoot>/node_modules/minimatch`
 *
 * `<packageRoot>` is `process.cwd()`, which for this lifecycle script is the root
 * of `@vizo-o/cdk-package` (in the publisher’s repo or under the consumer’s
 * `node_modules/@vizo-o/cdk-package`). If either path is missing, it no-ops (exit 0).
 *
 * When you can remove this script
 * --------------------------------
 * Consider deleting this hook and the `postinstall` entry when ALL of the following
 * hold in realistic installs (CI + consumer apps):
 * - `npm audit --audit-level=high` is clean without this copy step.
 * - `node_modules/aws-cdk-lib/node_modules/minimatch` either disappears or already
 *   matches the patched version from overrides.
 * - CDK tests and consuming CDK apps still pass.
 *
 * Until then, keep it: removing it may restore a vulnerable nested copy in some npm layouts.
 *
 * `brace-expansion`: same pattern — aws-cdk-lib can nest a vulnerable copy; replace
 * it with the hoisted `node_modules/brace-expansion` when both exist.
 */
import fs from 'node:fs'
import path from 'node:path'

const root = process.cwd()

function syncNestedPackage(nestedName) {
    const nested = path.join(
        root,
        'node_modules',
        'aws-cdk-lib',
        'node_modules',
        nestedName,
    )
    const hoisted = path.join(root, 'node_modules', nestedName)
    if (!fs.existsSync(nested) || !fs.existsSync(hoisted)) {
        return
    }
    fs.rmSync(nested, { recursive: true })
    fs.cpSync(hoisted, nested, { recursive: true })
}

syncNestedPackage('minimatch')
syncNestedPackage('brace-expansion')
