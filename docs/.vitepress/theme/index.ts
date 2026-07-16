import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import IrcTerminal from './components/IrcTerminal.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('IrcTerminal', IrcTerminal)
  },
} satisfies Theme
