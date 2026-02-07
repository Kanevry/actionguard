# Contributing to ActionGuard

Thank you for your interest in contributing to ActionGuard! This guide will help you get started.

## Development Setup

1. **Fork and clone the repository:**
   ```bash
   git clone https://github.com/your-username/actionguard.git
   cd actionguard
   ```

2. **Install dependencies:**
   ```bash
   pnpm install
   ```

3. **Build all packages:**
   ```bash
   pnpm run build
   ```

4. **Run tests:**
   ```bash
   pnpm run test
   ```

## Development Workflow

1. Create a new branch from `main`:
   ```bash
   git checkout -b feature/my-feature
   ```

2. Make your changes and add tests.

3. Run checks:
   ```bash
   pnpm run lint
   pnpm run typecheck
   pnpm run test
   ```

4. Add a changeset (for publishable changes):
   ```bash
   pnpm changeset
   ```

5. Commit using [Conventional Commits](https://www.conventionalcommits.org/):
   ```bash
   git commit -m "feat: add new auth provider"
   ```

6. Push and create a Pull Request.

## Project Structure

```
packages/
  core/    - Main actionguard package (MIT)
  cli/     - CLI tool (MIT)
  pro/     - Pro features (Commercial)
examples/  - Example implementations
docs/      - Documentation site
```

## Code Style

We use [Biome](https://biomejs.dev/) for linting and formatting. Run `pnpm run lint` before committing.

## Testing

We use [Vitest](https://vitest.dev/) for testing. Please add tests for any new functionality.

## Questions?

Feel free to open a [Discussion](https://github.com/actionguard/actionguard/discussions) if you have questions.
