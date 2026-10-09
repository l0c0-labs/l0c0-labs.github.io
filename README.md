# L0c0 — Laboratory of Cyber Operations

Hugo + Blowfish, hosted on GitHub Pages at https://l0c0.org.

## Homepage

The custom homepage is in `layouts/index.html`; its styles are in `static/css/l0c0.css`. Blowfish still renders article pages. All homepage assets are local; no JavaScript or external fonts are required.

## Publish an article

Create `content/posts/your-article/index.md` and place its images in the same folder. Use this front matter:

```toml
+++
title = "Your article title"
date = 2026-10-09
description = "A short description of your findings."
draft = false
+++
```

Write the article below the front matter. Link images with `![Image description](image.png)`. Published posts automatically appear on the homepage in reverse chronological order; drafts are excluded by Hugo's normal production build.

Pushing to `main` triggers the existing GitHub Pages deployment workflow.
