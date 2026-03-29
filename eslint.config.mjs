import { createSharedConfig } from '@vizo-o/dev-tools/eslint-config/eslint.config.mjs'
import globals from 'globals'

const config = createSharedConfig({
    isNodeEnv: true,
    tsconfigPath: './tsconfig.eslint.json',
})

config.push({
    files: ['test/**/*.ts'],
    languageOptions: {
        parserOptions: {
            project: './tsconfig.eslint.json',
        },
        globals: {
            ...globals.jest,
            NodeJS: 'readonly',
        },
    },
})

export default config
