# Sentinel

> 🔥 Advanced API monitoring and analytics platform with a cyberpunk tactical HUD interface

## 🎯 About

Sentinel is a cutting-edge API monitoring and analytics platform built with a modern monorepo architecture. Features a stunning cyberpunk-inspired interface with green accent colors and tactical HUD elements.

## 🏗️ Project Structure

```
sentinel/
├── apps/
│   ├── collector/      # Data collection service (Node + Elysia)
│   ├── console/        # Web dashboard (React + Vite)
│   └── query/          # Query API service (Node + Elysia)
└── tinybird/           # Analytics data pipeline (Tinybird)
```

## 🚀 Getting Started

### Prerequisites

- Node.js >= 18.0.0
- npm or bun

### Installation

Install all dependencies across the monorepo:

```bash
npm install
```

### Development

Run all apps in development mode:

```bash
npm run dev
```

The console will be available at `http://localhost:3000` and automatically load the dashboard.

Run individual apps:

```bash
npm run collector:dev   # Run collector service (port 6000)
npm run console:dev     # Run web console (port 3000)
npm run query:dev       # Run query service (port 8000)
```

### Building

Build all apps:

```bash
npm run build
```

## 🎨 Features

- **Cyberpunk UI**: Tactical HUD design with corner brackets and green accents
- **Real-time Monitoring**: Track API requests and performance metrics
- **Analytics Dashboard**: Comprehensive analytics with charts and visualizations
- **Alert System**: Set up alerts for API issues
- **Project Management**: Multi-project and multi-org support

## 📦 Workspaces

### apps/collector

Data collection service that ingests API monitoring data.

### apps/console

Web-based dashboard for visualizing and managing API monitoring data. Features:
- Auto-loads dashboard (no authentication in dev mode)
- Green cyberpunk theme
- Tactical HUD interface
- Real-time analytics

### apps/query

Query API service for retrieving and analyzing monitoring data.

### tinybird

Analytics data pipeline configuration and deployment scripts.

## 🛠️ Scripts

- `npm run dev` - Start all apps in development mode
- `npm run build` - Build all apps
- `npm run test` - Run all tests
- `npm run lint` - Lint all packages
- `npm run format` - Format code with Prettier
- `npm run clean` - Clean all build artifacts and node_modules

## 🎨 Design System

- **Accent Color**: `#00ff41` (Matrix green)
- **Background**: Pure black (#000)
- **Text**: White (#fff)
- **Theme**: Cyberpunk / Tactical HUD
- **Fonts**: System fonts + monospace

## 📝 License

Distributed under the terms of the [GNU General Public License v3.0](LICENSE).

---

**Sentinel** - Monitoring your APIs like a cyber guardian 🛡️
