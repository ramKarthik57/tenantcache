# Technical Presentation Slides: TenantCache

This directory contains the conference and defense slide deck for **TenantCache: Automated Differential Verification of Cache Isolation in Multi-Tenant Web Applications**.

---

## Viewing and Compiling the Presentation

The presentation is formatted using [Marp Markdown](https://marp.app/), the open-source presentation framework.

### Option 1: View in VS Code
1. Install the **Marp for VS Code** extension (`marp-team.marp-vscode`).
2. Open `slides.md` and click the **Open Preview** button in the top right.
3. Export directly to PDF, PPTX, or HTML via the Marp icon.

### Option 2: Render via Marp CLI
```bash
# Install Marp CLI globally via npm
npm install -g @marp-team/marp-cli

# Render to HTML
npx @marp-team/marp-cli slides.md -o slides.html

# Render to PDF
npx @marp-team/marp-cli slides.md -o slides.pdf --allow-local-files
```
