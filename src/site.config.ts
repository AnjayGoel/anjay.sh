import type { SiteConfig } from "@/types";
import { ExpressiveCodeTheme, type AstroExpressiveCodeOptions } from "astro-expressive-code";

export const siteConfig: SiteConfig = {
	// Used as both a meta property (src/components/BaseHead.astro L:31 + L:49) & the generated satori png (src/pages/og-image/[slug].png.ts)
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
	// HTML lang property, found in src/layouts/Base.astro L:18 & astro.config.ts L:48
	lang: "en-US",
	// Meta property, found in src/components/BaseHead.astro L:42
	ogLocale: "en_US",
	// Option to sort posts by updatedDate if set to true (if property exists). Default (false) will sort by publishDate
	sortPostsByUpdatedDate: false,
	// Used to construct the meta title property found in src/components/BaseHead.astro L:11, and webmanifest name found in astro.config.ts L:42
	title: "Anjay Goel",
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

// Custom warm-toned themes that match the site's cream/sienna UI palette.
const warmPaperLight = new ExpressiveCodeTheme({
	colors: { "editor.background": "#efe6d3", "editor.foreground": "#3a3429" },
	name: "warm-paper-light",
	tokenColors: [
		{
			scope: ["comment", "punctuation.definition.comment"],
			settings: { fontStyle: "italic", foreground: "#9b8e72" },
		},
		{
			scope: ["keyword", "storage", "storage.type", "storage.modifier"],
			settings: { fontStyle: "bold", foreground: "#8a4423" },
		},
		{
			scope: ["string", "string.quoted", "string.template"],
			settings: { foreground: "#5e7a4d" },
		},
		{
			scope: ["constant.numeric", "constant.language", "constant.character"],
			settings: { foreground: "#9c5e3a" },
		},
		{
			scope: ["entity.name.function", "support.function", "meta.function-call"],
			settings: { foreground: "#5b6a8c" },
		},
		{
			scope: ["entity.name.type", "support.type", "entity.name.class", "support.class"],
			settings: { foreground: "#7a5b3a" },
		},
		{
			scope: ["variable", "variable.parameter", "variable.other"],
			settings: { foreground: "#3a3429" },
		},
		{
			scope: ["keyword.operator", "punctuation"],
			settings: { foreground: "#5a4a37" },
		},
		{
			scope: ["entity.other.attribute-name"],
			settings: { fontStyle: "italic", foreground: "#9c5e3a" },
		},
		{
			scope: ["meta.tag", "entity.name.tag"],
			settings: { foreground: "#8a4423" },
		},
		{
			scope: ["variable.other.property", "meta.object-literal.key", "support.type.property-name"],
			settings: { foreground: "#7a5b3a" },
		},
	],
	type: "light",
});

const warmPaperDark = new ExpressiveCodeTheme({
	colors: { "editor.background": "#1d1a13", "editor.foreground": "#e0d8c4" },
	name: "warm-paper-dark",
	tokenColors: [
		{
			scope: ["comment", "punctuation.definition.comment"],
			settings: { fontStyle: "italic", foreground: "#7a6f54" },
		},
		{
			scope: ["keyword", "storage", "storage.type", "storage.modifier"],
			settings: { fontStyle: "bold", foreground: "#c89761" },
		},
		{
			scope: ["string", "string.quoted", "string.template"],
			settings: { foreground: "#9bb37b" },
		},
		{
			scope: ["constant.numeric", "constant.language", "constant.character"],
			settings: { foreground: "#d09a6e" },
		},
		{
			scope: ["entity.name.function", "support.function", "meta.function-call"],
			settings: { foreground: "#a3b3d4" },
		},
		{
			scope: ["entity.name.type", "support.type", "entity.name.class", "support.class"],
			settings: { foreground: "#c4a777" },
		},
		{
			scope: ["variable", "variable.parameter", "variable.other"],
			settings: { foreground: "#e0d8c4" },
		},
		{
			scope: ["keyword.operator", "punctuation"],
			settings: { foreground: "#a89b80" },
		},
		{
			scope: ["entity.other.attribute-name"],
			settings: { fontStyle: "italic", foreground: "#d09a6e" },
		},
		{
			scope: ["meta.tag", "entity.name.tag"],
			settings: { foreground: "#c89761" },
		},
		{
			scope: ["variable.other.property", "meta.object-literal.key", "support.type.property-name"],
			settings: { foreground: "#c4a777" },
		},
	],
	type: "dark",
});

// https://expressive-code.com/reference/configuration/
export const expressiveCodeOptions: AstroExpressiveCodeOptions = {
	styleOverrides: {
		borderRadius: "4px",
		codeFontFamily:
			'ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;',
		codeFontSize: "0.875rem",
		codeLineHeight: "1.7142857rem",
		codePaddingInline: "1rem",
		frames: {
			frameBoxShadowCssValue: "none",
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
	themes: [warmPaperDark, warmPaperLight],
	useThemedScrollbars: false,
};
