import js from "@eslint/js";
import prettier from "eslint-config-prettier";

export default [
  js.configs.recommended,
  prettier,
  {
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: "module",
      globals: {
        // Node.js globals
        process: "readonly",
        console: "readonly",
        __filename: "readonly",
        __dirname: "readonly",
        // Browser globals
        window: "readonly",
        document: "readonly",
        fetch: "readonly",
        URL: "readonly",
        Uint8Array: "readonly",
        ArrayBuffer: "readonly",
      },
    },
    rules: {
      "no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
        },
      ],
      "no-console": "off",
    },
  },
  {
    ignores: ["dist/", "node_modules/", "model/", "example/vendor/"],
  },
];
