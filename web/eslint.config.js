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
    selector: 'MemberExpression[property.name=/^(innerHTML|outerHTML)$/]',
    message: 'innerHTML/outerHTML are forbidden: use textContent or DOM APIs.',
  },
  {
    selector: "CallExpression[callee.property.name='insertAdjacentHTML']",
    message: 'insertAdjacentHTML is forbidden.',
  },
  {
    selector: "CallExpression[callee.property.name='write'][callee.object.name='document']",
    message: 'document.write is forbidden.',
  },
];

export default tseslint.config(
  { ignores: ['dist', 'coverage', 'playwright-report', 'test-results', 'src/contract/**'] },
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
      'no-restricted-syntax': ['error', ...htmlInjectionSinks],
    },
  },
  jsxA11y.flatConfigs.strict,
  {
    files: ['*.config.{js,ts}', 'tests/**'],
    languageOptions: { globals: { ...globals.node } },
  },
  {
    files: ['eslint.config.js'],
    ...tseslint.configs.disableTypeChecked,
  },
  prettier,
);
