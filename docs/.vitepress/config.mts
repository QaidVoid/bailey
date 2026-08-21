import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'bailey',
  description: 'A layered, deny-by-default sandbox for running untrusted programs on Linux',
  lang: 'en-US',
  cleanUrls: true,
  lastUpdated: true,

  // Warm, muted token colours. The default palette is cool-toned and sits at
  // odds with the stone and amber everything else is built from.
  markdown: {
    theme: { light: 'vitesse-light', dark: 'vitesse-dark' },
  },

  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: '/favicon.svg' }],
    ['meta', { name: 'theme-color', content: '#c8801a' }],
  ],

  themeConfig: {
    logo: { light: '/logo.svg', dark: '/logo-dark.svg' },

    nav: [
      { text: 'Guide', link: '/guide/what-is-bailey' },
      { text: 'Reference', link: '/reference/cli' },
      { text: 'Security', link: '/security/model' },
      { text: 'Status', link: '/roadmap' },
    ],

    sidebar: {
      '/guide/': [
        {
          text: 'Introduction',
          items: [
            { text: 'What is bailey', link: '/guide/what-is-bailey' },
            { text: 'Installation', link: '/guide/installation' },
            { text: 'Quick start', link: '/guide/quick-start' },
          ],
        },
        {
          text: 'Core concepts',
          items: [
            { text: 'The policy model', link: '/guide/policy-model' },
            { text: 'Enforcement layers', link: '/guide/enforcement' },
            { text: 'Namespace isolation', link: '/guide/isolation' },
            { text: 'Network confinement', link: '/guide/network' },
            { text: 'Environment and storage', link: '/guide/environment' },
          ],
        },
        {
          text: 'Using bailey',
          items: [
            { text: 'A confined shell', link: '/guide/shell' },
            { text: 'Shell integration', link: '/guide/hook' },
            { text: 'Configuration', link: '/guide/configuration' },
            { text: 'Trusting a config', link: '/guide/trusting-a-config' },
            { text: 'Profiles', link: '/guide/profiles' },
            { text: 'Auditing a program', link: '/guide/audit' },
            { text: 'Lifecycle hooks', link: '/guide/hooks' },
            { text: 'Knowing what was enforced', link: '/guide/diagnostics' },
            { text: 'Troubleshooting', link: '/guide/troubleshooting' },
          ],
        },
        {
          text: 'Recipes',
          items: [
            { text: 'A downloaded binary', link: '/guide/recipes/untrusted-binary' },
            { text: 'A native game', link: '/guide/recipes/native-game' },
            { text: 'A coding agent', link: '/guide/recipes/coding-agent' },
          ],
        },
      ],
      '/reference/': [
        {
          text: 'Reference',
          items: [
            { text: 'CLI', link: '/reference/cli' },
            { text: 'Configuration file', link: '/reference/config' },
            { text: 'Trace format', link: '/reference/trace' },
            { text: 'What it costs', link: '/reference/benchmarks' },
            { text: 'Kernel requirements', link: '/reference/kernel' },
          ],
        },
      ],
      '/security/': [
        {
          text: 'Security',
          items: [
            { text: 'Threat model', link: '/security/model' },
            { text: 'Known limitations', link: '/security/limitations' },
            { text: 'Privilege model', link: '/security/privilege' },
          ],
        },
      ],
    },

    socialLinks: [
      { icon: 'github', link: 'https://github.com/QaidVoid/bailey' },
    ],

    editLink: {
      pattern: 'https://github.com/QaidVoid/bailey/edit/main/docs/:path',
      text: 'Edit this page on GitHub',
    },

    search: {
      provider: 'local',
    },

    footer: {
      message: 'Released under the MIT or Apache-2.0 license.',
      copyright: 'Copyright © 2026 QaidVoid',
    },

    outline: [2, 3],
  },
})
