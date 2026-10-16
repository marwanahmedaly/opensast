# Dashboard design tokens

`tokens.json` defines shared colors, typography and spacing. The dashboard's standalone stylesheet is `src/aisast/product/static/style.css`. Its initial generated `:root` token block stays in sync with these base token values. Dashboard-specific semantic overrides use the website’s dark graphite/cyan palette: `#11171d` to `#233940` backgrounds, `#42d9e8` accents and light text. These overrides live immediately after the shared block in the stylesheet. The dashboard does not require the research website or slide assets.

## Visual conventions

Use graphite surfaces and restrained cyan accents, local Arial/Helvetica and system monospace fonts, square corners, visible focus and consistent spacing. Keep forms labeled and keyboard accessible. Do not depend on remote fonts or icon requests.

Verdict colors supplement written labels: danger for vulnerable, success for not vulnerable, amber for unresolved and purple for system errors. A negative model verdict is not proof that code is safe. Preserve the distinction between unresolved evidence and execution errors.
