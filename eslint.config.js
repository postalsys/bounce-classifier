// Shared lint baseline for the Postal Systems / Nodemailer packages: eslint:recommended
// plus the rules of the retired eslint-config-nodemailer, with formatting left to Prettier.
// ESM form of the shared CommonJS template; keep the rule set identical across repos
// except for the "Repo-specific" block at the end.

import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import globals from 'globals';

export default [
    {
        ignores: ['node_modules/**', 'coverage/**', 'dist/**', 'model/**', 'example/vendor/**']
    },
    js.configs.recommended,
    {
        files: ['**/*.js', '**/*.mjs', '**/*.cjs'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType: 'module',
            globals: { ...globals.node }
        },
        rules: {
            'no-await-in-loop': 'error',
            'no-div-regex': 'error',
            strict: ['error', 'global'],
            eqeqeq: 'error',
            'dot-notation': 'error',
            curly: 'error',
            'no-unused-expressions': ['error', { allowShortCircuit: true }],
            'no-unused-vars': ['error', { varsIgnorePattern: '^_', argsIgnorePattern: '^_', caughtErrorsIgnorePattern: '^_' }],
            'handle-callback-err': 'error',
            'no-new': 'error',
            'new-cap': 'error',
            'no-eval': 'error',
            'no-invalid-this': 'error',
            radix: ['error', 'always'],
            'no-use-before-define': ['error', 'nofunc'],
            'callback-return': ['error', ['callback', 'cb', 'done']],
            'no-redeclare': 'error',
            'block-scoped-var': 'error',
            'no-sequences': 'error',
            'no-throw-literal': 'error',
            'no-useless-call': 'error',
            'no-useless-concat': 'error',
            'no-void': 'error',
            yoda: 'error',
            'no-var': 'error',
            'no-bitwise': 'error',
            'no-lonely-if': 'error',
            'arrow-body-style': ['error', 'as-needed'],
            'prefer-arrow-callback': 'error',
            'object-shorthand': 'error',
            'prefer-spread': 'error',
            'no-prototype-builtins': 'off'
        }
    },
    {
        files: ['**/*.cjs'],
        languageOptions: {
            sourceType: 'commonjs'
        }
    },
    // Repo-specific: overrides go here, each with a one-line reason
    {
        // src/index.js also runs in the browser (the GitHub Pages demo) and feature-detects window/document
        files: ['src/**/*.js'],
        languageOptions: {
            globals: { ...globals.node, ...globals.browser }
        }
    },
    {
        // Test loops classify one message at a time against shared module state (18 sites)
        files: ['test/**'],
        rules: {
            'no-await-in-loop': 'off'
        }
    },
    prettier
];
