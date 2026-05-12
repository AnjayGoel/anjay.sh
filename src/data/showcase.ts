export interface ShowcaseItem {
	name: string;
	href: string;
	stack: string;
	badge?: string;
	desc: string;
}

export const showcase: ShowcaseItem[] = [
	{
		name: "RedScout",
		href: "https://github.com/AnjayGoel/RedScout",
		stack: "Redis · Monitoring · CLI",
		badge: "OSS",
		desc: "A Redis monitoring tool that provides namespace-level insights into your Redis database. Unlike traditional tools, It breaks down memory usage, key TTLs, and operations per second by logical namespaces.",
	},
	{
		name: "DashReels",
		href: "https://play.google.com/store/apps/details?id=com.dashtoon.video.reels&hl=en_IN",
		stack: "App ·  Short Videos",
		badge: "20M+ installs",
		desc: "A mobile entertainment app offering short-form video content across multiple genres. Features include free short dramas, a personalized recommendation system, and an engaging, user-friendly experience.",
	},
	{
		name: "DashToon",
		href: "https://play.google.com/store/apps/details?id=com.dashtoon.app&hl=en_IN",
		stack: "App · Comics",
		badge: "1M+ installs",
		desc: "A mobile application focused on comics and webtoons. Provides users with access to a wide variety of digital comics and manga content with an intuitive reading experience.",
	},
	{
		name: "Generalised Stable Roommate",
		href: "https://github.com/AnjayGoel/stable-roommate-generalised",
		stack: "Python · Algorithms",
		badge: "OSS",
		desc: "An algorithm & webapp to automatically group people into optimal teams based on their individual preferences.",
	},
];
