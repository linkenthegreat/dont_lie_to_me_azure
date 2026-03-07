# Contributing to Don't Lie To Me – Azure

Thank you for your interest in contributing! This document provides guidelines
to help you get started quickly.

---

## Code of Conduct

Be respectful, constructive, and inclusive. We follow the
[Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

---

## How to contribute

### Reporting bugs or requesting features

1. Search [existing issues](https://github.com/linkenthegreat/dont_lie_to_me_azure/issues)
   to avoid duplicates.
2. Open a new issue using one of the provided templates.
3. Include as much context as possible (OS, Python version, error messages,
   steps to reproduce).

### Submitting a pull request

1. Fork the repository and create a feature branch from `main`:
   ```bash
   git checkout -b feature/my-new-feature
   ```
2. Follow the setup instructions in [docs/setup.md](setup.md).
3. Make your changes and add or update tests where appropriate.
4. Ensure the code follows the style guide (see below).
5. Commit with a clear message:
   ```
   feat: add rate-limiting middleware to all endpoints
   ```
6. Push your branch and open a pull request against `main`.
7. Fill in the pull request template and link any related issues.

---

## Project structure

```
dont_lie_to_me_azure/
├── src/
│   ├── backend/           # Azure Functions (Python v2)
│   │   ├── function_app.py
│   │   ├── host.json
│   │   ├── requirements.txt
│   │   ├── local.settings.json.example
│   │   └── shared/        # Reusable helpers
│   │       ├── ai_client.py
│   │       ├── keyvault.py
│   │       └── storage.py
│   └── frontend/          # Static web UI
│       ├── index.html
│       ├── style.css
│       └── app.js
├── infra/                 # Bicep IaC templates
│   ├── main.bicep
│   └── modules/
│       ├── functions.bicep
│       ├── keyvault.bicep
│       └── storage.bicep
├── docs/                  # Documentation
│   ├── architecture.md
│   ├── setup.md
│   └── CONTRIBUTING.md
└── README.md
```

---

## Code style

### Python (backend)

- Follow [PEP 8](https://peps.python.org/pep-0008/).
- Use type hints where practical.
- Docstrings for all public functions and classes.
- Lint with `flake8` and format with `black`:
  ```bash
  pip install black flake8
  black src/backend/
  flake8 src/backend/
  ```

### JavaScript (frontend)

- Use ES6+ features.
- Prefer `const` / `let` over `var`.
- No external dependencies required for the starter – keep it vanilla JS.

### Bicep (infra)

- Use modules for logical separation.
- Add `@description` decorators to all parameters.
- Follow [Bicep best practices](https://learn.microsoft.com/azure/azure-resource-manager/bicep/best-practices).

---

## Testing

```bash
cd src/backend
pip install pytest
pytest tests/ -v
```

Please add tests for any new backend functionality under `src/backend/tests/`.

---

## Branch naming conventions

| Type | Pattern | Example |
|------|---------|---------|
| Feature | `feature/<short-description>` | `feature/add-image-ocr` |
| Bug fix | `fix/<short-description>` | `fix/keyvault-timeout` |
| Documentation | `docs/<short-description>` | `docs/update-setup-guide` |
| Infrastructure | `infra/<short-description>` | `infra/add-cosmos-module` |

---

## Commit message format

We loosely follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>: <short description>

[optional body]
[optional footer]
```

Types: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `infra`.

---

## Questions?

Open a [GitHub Discussion](https://github.com/linkenthegreat/dont_lie_to_me_azure/discussions)
or ping the maintainers in an issue.
