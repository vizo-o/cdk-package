/**
 * Pre-release gate: clean tree, lint:fix (+ commit if needed), type-check, test,
 * audit:high, build — each optional step uses npm --if-present where applicable.
 */
import { execSync } from 'child_process'
import { existsSync, readFileSync } from 'fs'
import { dirname, join } from 'path'
import { fileURLToPath } from 'url'

const packageRoot = join(dirname(fileURLToPath(import.meta.url)), '..')

function run(cmd) {
    execSync(cmd, {
        cwd: packageRoot,
        stdio: 'inherit',
        env: process.env,
    })
}

function gitPorcelain() {
    return execSync('git status --porcelain', {
        cwd: packageRoot,
        encoding: 'utf8',
    }).trim()
}

function readPackageName() {
    const raw = readFileSync(join(packageRoot, 'package.json'), 'utf8')
    const { name } = JSON.parse(raw)
    return typeof name === 'string' ? name : ''
}

if (!existsSync(join(packageRoot, 'package.json'))) {
    console.error('pre-release: package.json not found next to scripts/')
    process.exit(1)
}

if (gitPorcelain()) {
    console.error(
        `pre-release: working tree must be clean before running (${readPackageName()})`,
    )
    process.exit(1)
}

run('npm run lint:fix')

if (gitPorcelain()) {
    run('git add -A')
    run('git commit -m "chore: apply lint fixes"')
}

if (gitPorcelain()) {
    console.error('pre-release: unexpected dirty tree after lint commit')
    process.exit(1)
}

run('npm run type-check --if-present')
run('npm run test --if-present')
run('npm run audit:high')
run('npm run build --if-present')
