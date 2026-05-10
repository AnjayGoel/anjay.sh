# anjay.sh

Source code for my personal site & blog at [anjay.sh](https://anjay.sh).

It's an [Astro](https://astro.build/) starter with a hand-built serif theme
(Newsreader / Inter / JetBrains Mono), light & dark mode, MDX, RSS, sitemap,
auto-generated OG images via [satori](https://github.com/vercel/satori),
[Giscus](https://giscus.app) comments, and on-demand webmentions. It's deployed
to [Cloudflare Pages](https://pages.cloudflare.com/).

The codebase is intentionally close to a usable theme — most personal details
live in [`src/site.config.ts`](./src/site.config.ts) (`profile`, `comments`,
`analytics`, `webmentions`). The showcase / projects list lives in
[`src/data/showcase.ts`](./src/data/showcase.ts).

## Make it your own

1. Fork the repo and clone.
2. Edit `src/site.config.ts` — set `title`, `author`, `description`, the
   `profile` block (name / socials / employer / alumni), and `comments` /
   `analytics` if you want them. Set or unset the optional fields to hide
   the corresponding UI / `<script>` tags.
3. Update `astro.config.ts` → `site` to your domain.
4. Replace `public/icon.png`, `public/social-card.png`, and (optionally)
   `public/avatar.png` with your own assets.
5. Replace or delete `src/content/post/*` — these are my posts.
6. Replace `src/data/showcase.ts` with your own projects (or empty the array
   to hide the Showcase page).
7. Update `public/google*.html` (Search Console verification) and
   `public/resume.pdf` to match your own — or remove them.

## Develop

```sh
pnpm install
pnpm dev          # dev server
pnpm build        # full production build (runs astro check + pagefind)
pnpm preview      # preview built site
pnpm format       # biome + prettier
```

## Layout

```
src/
  site.config.ts          # author / profile / comments / analytics
  layouts/                # Base + BlogPost
  components/             # Header, Footer, ThemeToggle, BaseHead, ...
  data/showcase.ts        # showcase entries
  content/post/*.md       # blog posts (Astro content collection)
  pages/                  # routes
public/                   # static assets served at site root
design-explorations/      # historical HTML mockups, not built
```

## License

MIT — see [LICENSE](./LICENSE). Do not reuse the post content under
`src/content/post/` or the personal images in `public/` without permission.
