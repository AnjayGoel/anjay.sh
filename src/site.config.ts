import type { SiteConfig } from "@/types";
import type { AstroExpressiveCodeOptions } from "astro-expressive-code";

export const siteConfig: SiteConfig = {
	// Used as both a meta property (src/components/BaseHead.astro) & the generated satori png (src/pages/og-image/[slug].png.ts).
	// Also used as the fallback for `profile.name` if not set below.
	author: "Anjay Goel",
	// Date.prototype.toLocaleDateString() parameters, found in src/utils/date.ts.
	date: {
		locale: "en-US",
		options: {
			day: "numeric",
			month: "short",
			year: "numeric",
		},
	},
	// Used as the default description meta property and webmanifest description
	description:
		"Hi!\nI am Anjay. I love to write about software development, technology and occasionally other stuff like economics & finance. I hope you find something interesting here.",
	// HTML lang property, found in src/layouts/Base.astro & astro.config.ts
	lang: "en-US",
	// Meta property, found in src/components/BaseHead.astro
	ogLocale: "en_US",
	// Option to sort posts by updatedDate if set to true (if property exists). Default (false) will sort by publishDate
	sortPostsByUpdatedDate: false,
	// Used to construct the meta title property found in src/components/BaseHead.astro, and webmanifest name found in astro.config.ts
	title: "Anjay Goel",

	// Author / personal info. Consumed by the About page, post byline, structured data, and OG images.
	// All fields are optional — leave them undefined to hide the corresponding link/markup.
	profile: {
		name: "Anjay Goel",
		email: "anjay.goel@gmail.com",
		github: "https://github.com/anjaygoel",
		linkedin: "https://www.linkedin.com/in/anjaygoel/",
		jobTitle: "Software Engineer",
		employer: "Dashtoon",
		employerUrl: "https://www.linkedin.com/company/dashtoon/",
		alumni: "IIT Kharagpur",
		avatar: "/avatar.png",
	},

	// Giscus (https://giscus.app) configuration for blog post comments.
	// Set to undefined to disable the comment widget on posts.
	comments: {
		repo: "anjaygoel/anjay.sh",
		repoId: "MDEwOlJlcG9zaXRvcnkzNzY2MjI0MjY=",
		category: "General",
		categoryId: "DIC_kwDOFnLNWs4CQ8t3",
	},

	// Optional analytics. Each provider is opt-in; leave fields undefined to skip the script.
	analytics: {
		googleAnalyticsId: "G-YMCFXDNKXR",
		goatcounterUrl: "https://anjaygoel.goatcounter.com/count",
	},
};

// Used to generate links in both the Header & Footer.
export const menuLinks: { path: string; title: string }[] = [
	{
		path: "/",
		title: "Home",
	},
	{
		path: "/posts/",
		title: "Posts",
	},
	{
		path: "/showcase/",
		title: "Showcase",
	},
	{
		path: "/about/",
		title: "About",
	},
];

// https://expressive-code.com/reference/configuration/
export const expressiveCodeOptions: AstroExpressiveCodeOptions = {
	styleOverrides: {
		borderRadius: "4px",
		codeBackground: ({ theme }) => (theme.type === "light" ? "#f0e9d6" : "#1a1715"),
		codeFontFamily:
			'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;',
		codeFontSize: "0.875rem",
		codeLineHeight: "1.7142857rem",
		codePaddingInline: "1rem",
		frames: {
			editorActiveTabBackground: ({ theme }) => (theme.type === "light" ? "#f0e9d6" : "#1a1715"),
			editorTabBarBackground: ({ theme }) => (theme.type === "light" ? "#ebe3cd" : "#15120e"),
			frameBoxShadowCssValue: "none",
			terminalBackground: ({ theme }) => (theme.type === "light" ? "#f0e9d6" : "#1a1715"),
			terminalTitlebarBackground: ({ theme }) => (theme.type === "light" ? "#ebe3cd" : "#15120e"),
		},
		uiLineHeight: "inherit",
	},
	themeCssSelector(theme, { styleVariants }) {
		// If one dark and one light theme are available
		// generate theme CSS selectors compatible with the site's dark mode switch
		if (styleVariants.length >= 2) {
			const baseTheme = styleVariants[0]?.theme;
			const altTheme = styleVariants.find((v) => v.theme.type !== baseTheme?.type)?.theme;
			if (theme === baseTheme || theme === altTheme) return `[data-theme='${theme.type}']`;
		}
		// return default selector
		return `[data-theme="${theme.name}"]`;
	},
	// One dark, one light theme => https://expressive-code.com/guides/themes/#available-themes
	themes: ["min-dark", "min-light"],
	useThemedScrollbars: false,
};
