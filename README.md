# L0C0 — Laboratory of Cyber Operations

Hugo + Blowfish, hosted on GitHub Pages at https://l0c0.org.

## Homepage

Custom blog layouts live in `layouts/`, with local CSS, search/filter JavaScript, and the OFL-licensed Roboto Mono font in `static/`. Roboto Mono distinguishes zero from O with a slashed zero. Article pages include a table of contents, code blocks, and responsive images.

Suggested topic values: `research`, `vulnerability`, `hardware-firmware`, `attack-trends`, `reviews`, `tools`. These are browsing topics, not limits on research scope. Add `categories = ["vulnerability"]` to an article front matter. Optional thumbnail: add `feature.png`, `cover.png`, or `thumbnail.png` to the article folder.

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
