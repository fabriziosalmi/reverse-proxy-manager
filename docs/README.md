# Documentation

This directory contains the VitePress-powered documentation for the Reverse Proxy Manager.

## Structure

```
docs/
├── .vitepress/          # VitePress configuration
│   └── config.mts       # Site configuration
├── guide/               # User guides
│   ├── getting-started.md
│   ├── installation.md
│   ├── configuration.md
│   ├── deployment.md
│   ├── architecture.md
│   └── troubleshooting.md
├── api-reference.md     # API documentation
├── index.md             # Home page
└── .nojekyll            # GitHub Pages compatibility

```

## Local Development

Install dependencies:
```bash
npm install
```

Start development server:
```bash
npm run docs:dev
```

The documentation will be available at http://localhost:5173

## Building

Build the documentation:
```bash
npm run docs:build
```

Preview the built documentation:
```bash
npm run docs:preview
```

## Deployment

Documentation is automatically deployed to GitHub Pages when changes are pushed to the `main` branch.

The deployment is handled by the GitHub Actions workflow at `.github/workflows/deploy-docs.yml`.

## Contributing to Documentation

When contributing to the documentation:

1. Make changes to the markdown files in the `docs/` directory
2. Test locally with `npm run docs:dev`
3. Build to verify no errors: `npm run docs:build`
4. Submit a pull request

## Documentation Pages

- **Home** (`index.md`): Overview and features
- **Getting Started** (`guide/getting-started.md`): Quick start guide
- **Installation** (`guide/installation.md`): Detailed installation instructions
- **Configuration** (`guide/configuration.md`): Configuration options and examples
- **Deployment** (`guide/deployment.md`): Production deployment guide
- **Architecture** (`guide/architecture.md`): System architecture documentation
- **Troubleshooting** (`guide/troubleshooting.md`): Common issues and solutions
- **API Reference** (`api-reference.md`): CLI and API documentation

## VitePress Configuration

The VitePress configuration is in `.vitepress/config.mts` and includes:

- Site title and description
- Navigation menu
- Sidebar structure
- Search functionality
- Edit links to GitHub
- Social links

## GitHub Pages

The documentation is deployed to: https://fabriziosalmi.github.io/reverse-proxy-manager/

GitHub Pages is configured to use the GitHub Actions deployment method.
