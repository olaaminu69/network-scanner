# Contributing to Network Security Scanner

Thank you for your interest in contributing!

## How to Contribute

### Reporting Bugs

1. Check if bug already reported in [Issues](https://github.com/olaaminu69/network-scanner/issues)
2. Create new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Python version and OS
   - Error messages or screenshots

### Suggesting Features

1. Open issue tagged `enhancement`
2. Describe the feature and use case
3. Explain why it's valuable
4. Provide examples if possible

### Pull Requests

1. Fork the repository
2. Create feature branch
```bash
   git checkout -b feature/amazing-feature
```
3. Make your changes
4. Test thoroughly
5. Commit with clear messages
```bash
   git commit -m "Add amazing feature"
```
6. Push to your fork
```bash
   git push origin feature/amazing-feature
```
7. Open Pull Request

## Development Guidelines

### Code Style

- Follow PEP 8
- Use descriptive variable names
- Add docstrings to functions
- Comment complex logic
- Keep functions focused and small

### Testing

Before submitting:
```bash
# Test each module
python scanner/network_discovery.py
python scanner/port_scanner.py
python scanner/vuln_scanner.py

# Test web app
sudo python app.py
```

### Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Be descriptive but concise
- Reference issues when applicable

**Examples:**
```
Add SSL/TLS vulnerability detection
Fix port scanner thread safety issue
Update README with usage examples
```

## Project Structure
```
network-scanner/
├── scanner/          # Core scanning modules
├── templates/        # Web UI templates
├── static/           # CSS/JS files
└── reports/          # Generated reports
```

## Questions?

Open an issue or reach out to the maintainer.

**Thank you for contributing!** 🎉
