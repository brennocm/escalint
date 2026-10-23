import js from '@eslint/js';
import prettier from 'eslint-config-prettier';
import jsxA11y from 'eslint-plugin-jsx-a11y';
import reactHooks from 'eslint-plugin-react-hooks';
import globals from 'globals';
import tseslint from 'typescript-eslint';

// Data in the snapshot is attacker-controlled (principal names, tags, policies).
// These selectors make the HTML-injection sinks a lint error everywhere.
const htmlInjectionSinks = [
  {
    selector: "JSXAttribute[name.name='dangerouslySetInnerHTML']",
    message: 'dangerouslySetInnerHTML is forbidden: render text nodes instead.',
  },
  {
    selector: "JSXAttribute[name.name='srcDoc']",
    message: 'srcDoc is forbidden: it renders HTML.',
  },
  {
    selector: 'MemberExpression[property.name=/^(innerHTML|outerHTML)$/]',
    message: 'innerHTML/outerHTML are forbidden: use textContent or DOM APIs.',
  },
  {
    // Computed access such as el['innerHTML'].
    selector: 'MemberExpression[computed=true][property.value=/^(innerHTML|outerHTML)$/]',
    message: 'innerHTML/outerHTML are forbidden: use textContent or DOM APIs.',
  },
  {
    selector:
      'CallExpression[callee.property.name=/^(insertAdjacentHTML|createContextualFragment)$/]',
    message: 'HTML parsing sinks are forbidden.',
  },
  {
    selector:
      "CallExpression[callee.property.name=/^(write|writeln)$/][callee.object.name='document']",
    message: 'document.write is forbidden.',
  },
];

// Tests and this file legitimately contain hostile strings as data.
const javascriptUrl = {
  selector: 'Literal[value=/^\\s*javascript:/i]',
  message: 'javascript: URLs are forbidden.',
};

export default tseslint.config(
  { ignores: ['dist', 'dist-demo', 'coverage', 'playwright-report', 'test-results', 'src/contract/**'] },
  js.configs.recommended,
  ...tseslint.configs.strictTypeChecked,
  ...tseslint.configs.stylisticTypeChecked,
  {
    languageOptions: {
      ecmaVersion: 2023,
      globals: { ...globals.browser },
      parserOptions: {
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    plugins: { 'react-hooks': reactHooks },
    rules: {
      ...reactHooks.configs.recommended.rules,
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      'no-restricted-syntax': ['error', ...htmlInjectionSinks, javascriptUrl],
    },
  },
  jsxA11y.flatConfigs.strict,
  {
    files: ['*.config.{js,ts}', 'tests/**'],
    languageOptions: { globals: { ...globals.node } },
  },
  {
    files: ['src/**/*.test.{ts,tsx}', 'tests/**'],
    rules: { 'no-restricted-syntax': ['error', ...htmlInjectionSinks] },
  },
  {
    files: ['scripts/**/*.mjs'],
    ...tseslint.configs.disableTypeChecked,
    languageOptions: {
      globals: { ...globals.node },
      parserOptions: { projectService: false, project: null },
    },
  },
  {
    files: ['eslint.config.js'],
    ...tseslint.configs.disableTypeChecked,
    rules: { ...tseslint.configs.disableTypeChecked.rules, 'no-restricted-syntax': 'off' },
  },
  prettier,
);
