import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'ferrixd',
  description:
    'Ferrous IRC Daemon — a memory-safe, IRCv3-complete IRC server in Rust: TLS-first, federated, load-tested to 100k connections.',
  lang: 'en-US',
  base: '/ferrixd/',
  lastUpdated: true,
  cleanUrls: true,

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/ferrixd/logo.svg' }],
    ['meta', { name: 'theme-color', content: '#d4581e' }],
    ['meta', { property: 'og:type', content: 'website' }],
    ['meta', { property: 'og:title', content: 'ferrixd — Ferrous IRC Daemon' }],
    [
      'meta',
      {
        property: 'og:description',
        content:
          'A memory-safe, IRCv3-complete IRC server in Rust. TLS-first, federated, 100k connections per node.',
      },
    ],
  ],

  themeConfig: {
    logo: '/logo.svg',

    nav: [
      { text: 'Guide', link: '/guide/what-is-ferrixd', activeMatch: '/guide/' },
      { text: 'Reference', link: '/reference/cli', activeMatch: '/reference/' },
      { text: 'Internals', link: '/internals/architecture', activeMatch: '/internals/' },
      {
        text: 'Install',
        link: '/guide/installation',
      },
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Getting Started',
          collapsed: false,
          items: [
            { text: 'What is ferrixd?', link: '/guide/what-is-ferrixd' },
            { text: 'Quick Start', link: '/guide/quick-start' },
            { text: 'Installation', link: '/guide/installation' },
          ],
        },
        {
          text: 'Running a Server',
          collapsed: false,
          items: [
            { text: 'Configuration', link: '/guide/configuration' },
            { text: 'TLS Certificates', link: '/guide/tls' },
            { text: 'Accounts & SASL', link: '/guide/accounts' },
            { text: 'Operators & Moderation', link: '/guide/operators' },
            { text: 'Channels', link: '/guide/channels' },
            { text: 'Message History', link: '/guide/history' },
          ],
        },
        {
          text: 'Growing the Network',
          collapsed: false,
          items: [
            { text: 'Federation (S2S)', link: '/guide/federation' },
            { text: 'WASM Plugins', link: '/guide/plugins' },
            { text: 'Observability', link: '/guide/observability' },
            { text: 'Production Deployment', link: '/guide/deployment' },
          ],
        },
      ],

      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'CLI', link: '/reference/cli' },
            { text: 'Configuration File', link: '/reference/config' },
            { text: 'IRC Commands', link: '/reference/commands' },
            { text: 'IRCv3 Capabilities', link: '/reference/capabilities' },
            { text: 'Modes & ISUPPORT', link: '/reference/modes' },
            { text: 'CHATHISTORY', link: '/reference/chathistory' },
            { text: 'Plugin ABI', link: '/reference/plugin-abi' },
            { text: 'S2S Protocol', link: '/reference/s2s-protocol' },
            { text: 'Metrics', link: '/reference/metrics' },
            { text: 'Limits & Defaults', link: '/reference/limits' },
          ],
        },
      ],

      '/internals/': [
        {
          text: 'Internals',
          items: [
            { text: 'Architecture', link: '/internals/architecture' },
            { text: 'Security Model', link: '/internals/security' },
            { text: 'Building & Testing', link: '/internals/development' },
            { text: 'Releasing', link: '/internals/releasing' },
            { text: 'Roadmap', link: '/internals/roadmap' },
          ],
        },
      ],
    },

    socialLinks: [{ icon: 'github', link: 'https://github.com/j-pfalzgraf/ferrixd' }],

    search: {
      provider: 'local',
    },

    editLink: {
      pattern: 'https://github.com/j-pfalzgraf/ferrixd/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },

    footer: {
      message: 'Dual-licensed under MIT or Apache-2.0.',
      copyright: 'ferrixd — the Ferrous IRC Daemon',
    },

    outline: { level: [2, 3] },
  },
})
