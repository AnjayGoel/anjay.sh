import type { Config } from "tailwindcss";
import { fontFamily } from "tailwindcss/defaultTheme";

export default {
	content: [
		"./src/**/*.{astro,html,js,jsx,md,svelte,ts,tsx,vue}",
		"!./src/pages/og-image/[slug].png.ts",
	],
	corePlugins: {
		// disable aspect ratio as per docs -> @tailwindcss/aspect-ratio (now removed)
		aspectRatio: false,
		borderOpacity: false,
		fontVariantNumeric: false,
		ringOffsetColor: false,
		ringOffsetWidth: false,
		scrollSnapType: false,
		textOpacity: false,
		// disable some core plugins as they are included in the css, even when unused
		touchAction: false,
	},
	darkMode: ["class", '[data-theme="dark"]'],
	plugins: [],
	theme: {
		extend: {
			colors: {
				accent: "hsl(var(--theme-accent) / <alpha-value>)",
				"accent-2": "hsl(var(--theme-accent-2) / <alpha-value>)",
				bgColor: "hsl(var(--theme-bg) / <alpha-value>)",
				link: "hsl(var(--theme-link) / <alpha-value>)",
				quote: "hsl(var(--theme-quote) / <alpha-value>)",
				textColor: "hsl(var(--theme-text) / <alpha-value>)",
				textMuted: "hsl(var(--theme-text-muted) / <alpha-value>)",
			},
			fontFamily: {
				sans: ["Inter", ...fontFamily.sans],
				serif: [...fontFamily.serif],
			},
			transitionProperty: {
				height: "height",
			},
		},
	},
} satisfies Config;
