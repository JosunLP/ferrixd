import { h } from 'vue'
import DefaultTheme from 'vitepress/theme'
import type { Theme } from 'vitepress'
import IrcTerminal from './components/IrcTerminal.vue'
import FxStats from './components/FxStats.vue'
import FxNotFound from './components/FxNotFound.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  Layout() {
    return h(DefaultTheme.Layout, null, {
      'not-found': () => h(FxNotFound),
    })
  },
  enhanceApp({ app }) {
    app.component('IrcTerminal', IrcTerminal)
    app.component('FxStats', FxStats)
  },
} satisfies Theme
