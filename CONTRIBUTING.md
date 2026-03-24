# Contributing to NetRecon

Thank you for considering contributing to NetRecon! All contributions are welcome.

## How to Contribute

### 1. Fork & Clone

```bash
git clone https://github.com/YOUR_USERNAME/netrecon.git
cd netrecon
```

### 2. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

### 3. Make Your Changes

- Keep code clean and commented
- Follow the existing module structure
- Test against Metasploitable 2 before submitting

### 4. Commit

Use conventional commit messages:

```bash
git commit -m "feat: add SMTP enumeration module"
git commit -m "fix: handle connection timeout in SSH module"
git commit -m "docs: update README with new flags"
```

### 5. Push & Pull Request

```bash
git push origin feature/your-feature-name
```

Then open a Pull Request on GitHub with a clear description of your changes.

---

## Code Style

- Python 3.8+ compatible
- Type hints encouraged
- Module structure: each service gets its own `enum_<service>()` function
- All findings must call `log()` with appropriate severity level
- No external dependencies beyond those in `requirements.txt` without discussion

---

## Ideas Welcome

- New service modules (SMTP, MySQL, PostgreSQL, VNC, RDP, SNMP)
- Additional CVE checks
- Output formats (HTML, CSV, XML)
- Performance improvements
- Documentation improvements

---

## Code of Conduct

- Be respectful and constructive
- Only contribute code intended for authorised security testing
- Do not submit anything designed to cause harm

---

## Licence

By contributing to NetRecon, you agree your contributions will be licensed under the MIT Licence.
