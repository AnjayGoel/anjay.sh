import type { SiteConfig } from "@/types";
import type { AstroExpressiveCodeOptions } from "astro-expressive-code";

export const siteConfig: SiteConfig = {
	author: "Anjay Goel",
	date: {
		locale: "en-US",
		options: {
			day: "numeric",
			month: "short",
			year: "numeric",
		},
	},
	description:
		"Hi!\nI am Anjay. I love to write about software development, technology and occasionally other stuff like economics & finance. I hope you find something interesting here.",
	lang: "en-US",
	ogLocale: "en_US",
	sortPostsByUpdatedDate: false,
	title: "Anjay Goel",
	hideThemeCredit: true,
	profile: {
		name: "Anjay Goel",
		email: "anjay.goel@gmail.com",
		github: "https://github.com/anjay-goel",
		linkedin: "https://www.linkedin.com/in/anjaygoel/",
		jobTitle: "Software Engineer",
		employer: "Dashtoon",
		employerUrl: "https://www.linkedin.com/company/dashtoon/",
		alumni: "IIT Kharagpur",
		avatar: "/avatar.png",
	},
	comments: {
		repo: "anjay-goel/anjay.sh",
		repoId: "MDEwOlJlcG9zaXRvcnkzNzY2MjI0MjY=",
		category: "General",
		categoryId: "DIC_kwDOFnLNWs4CQ8t3",
	},
	analytics: {
		googleAnalyticsId: "G-YMCFXDNKXR",
		goatcounterUrl: "https://anjaygoel.goatcounter.com/count",
	},
};

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
		if (styleVariants.length >= 2) {
			const baseTheme = styleVariants[0]?.theme;
			const altTheme = styleVariants.find((v) => v.theme.type !== baseTheme?.type)?.theme;
			if (theme === baseTheme || theme === altTheme) return `[data-theme='${theme.type}']`;
		}
		return `[data-theme="${theme.name}"]`;
	},
	themes: ["min-dark", "min-light"],
	useThemedScrollbars: false,
};
