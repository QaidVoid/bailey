import { defineConfig } from 'vitepress'

export default defineConfig({
  title: 'bailey',
  description: 'A layered, deny-by-default sandbox for running untrusted programs on Linux',
  lang: 'en-US',
  cleanUrls: true,
  lastUpdated: true,

  head: [
    ['meta', { name: 'theme-color', content: '#3c8772' }],
  ],

  themeConfig: {
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
      copyright: 'Copyright © 2026 bailey contributors',
    },

    outline: [2, 3],
  },
})
