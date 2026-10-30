import js from '@eslint/js'
import globals from 'globals'
import reactHooks from 'eslint-plugin-react-hooks'
import tseslint from 'typescript-eslint'
export default tseslint.config({ ignores: ['dist'] }, js.configs.recommended, ...tseslint.configs.recommended, reactHooks.configs['recommended-latest'], { languageOptions: { globals: globals.browser } })
