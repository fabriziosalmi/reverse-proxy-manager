import { defineConfig } from 'vitepress'

export default defineConfig({
    title: "Reverse Proxy Manager",
    description: "A centralized proxy management system",
    ignoreDeadLinks: true,
    themeConfig: {
        nav: [
            { text: 'Home', link: '/' },
            { text: 'Guide', link: '/guide/getting-started' },
            { text: 'API', link: '/api-reference' }
        ],

        sidebar: [
            {
                text: 'Guide',
                items: [
                    { text: 'Getting Started', link: '/guide/getting-started' },
                    { text: 'Configuration', link: '/guide/configuration' },
                    { text: 'Node Discovery', link: '/guide/node-discovery' }
                ]
            },
            {
                text: 'Security',
                items: [
                    { text: 'WAF', link: '/guide/waf' },
                    { text: 'GeoIP', link: '/guide/geoip' },
                    { text: 'SSL Management', link: '/guide/ssl' }
                ]
            },
            {
                text: 'Performance',
                items: [
                    { text: 'Caching', link: '/guide/caching' }
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
        ]
    }
})
