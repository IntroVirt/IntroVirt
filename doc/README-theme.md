# Doxygen theme

The HTML docs use the **doxygen-awesome-css** theme for a modern look and dark mode.

- **Source:** https://github.com/jothepro/doxygen-awesome-css
- **Version used:** v2.4.1 (compatible with Doxygen 1.9.x–1.14.x)

Files in this directory:

- `doxygen-awesome.css` – main theme styles (light/dark via `prefers-color-scheme` or toggle)
- `doxygen-awesome-darkmode-toggle.js` – optional dark/light toggle button in the nav bar
- `doxygen-awesome-footer.html` – injects the toggle script into generated pages

To update the theme, replace the CSS and JS with the desired release from the repo above and re-run `ninja doc`.
