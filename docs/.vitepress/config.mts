import { defineConfig } from 'vitepress'

export default defineConfig({
  title: "Reverse Proxy Manager",
  description: "A centralized proxy management system for distributed proxy nodes",
  base: '/reverse-proxy-manager/',
  
  ignoreDeadLinks: [
    // Ignore localhost links in documentation
    /^https?:\/\/localhost/,
  ],

  themeConfig: {
    nav: [
      { text: 'Home', link: '/' },
      { text: 'Guide', link: '/guide/getting-started' },
      { text: 'API', link: '/api-reference' },
      { text: 'GitHub', link: 'https://github.com/fabriziosalmi/reverse-proxy-manager' }
    ],

    sidebar: [
      {
        text: 'Introduction',
        items: [
          { text: 'Overview', link: '/' },
          { text: 'Getting Started', link: '/guide/getting-started' }
        ]
      },
      {
        text: 'Setup',
        items: [
          { text: 'Installation', link: '/guide/installation' },
          { text: 'Configuration', link: '/guide/configuration' },
          { text: 'Deployment', link: '/guide/deployment' }
        ]
      },
      {
        text: 'Advanced',
        items: [
          { text: 'Architecture', link: '/guide/architecture' },
          { text: 'Troubleshooting', link: '/guide/troubleshooting' }
        ]
      },
      {
        text: 'Reference',
        items: [
          { text: 'API Reference', link: '/api-reference' }
        ]
      }
    ],

    socialLinks: [
      { icon: 'github', link: 'https://github.com/fabriziosalmi/reverse-proxy-manager' }
    ],

    footer: {
      message: 'Released under the MIT License.',
      copyright: 'Copyright © 2024-present'
    },

    search: {
      provider: 'local'
    },

    editLink: {
      pattern: 'https://github.com/fabriziosalmi/reverse-proxy-manager/edit/main/docs/:path',
      text: 'Edit this page on GitHub'
    }
  }
})
