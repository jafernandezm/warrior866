import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightThemeObsidian from 'starlight-theme-obsidian';
import starlightLinksValidator from 'starlight-links-validator';

export default defineConfig({
    site: "https://jafernandezm.github.io",
    base: "/warrior866",
    integrations: [
        starlight({
            title: {
                es: 'Warrior866 - Writeups',
                en: 'Warrior866 - Writeups',
            },
            description: 'Writeups de HackTheBox, Challenges y OffSec',
            credits: false,
            defaultLocale: 'es',
            locales: {
                es: { label: 'Español', lang: 'es' },
                en: { label: 'English', lang: 'en' },
            },
            social: [
                { icon: 'github', label: 'GitHub', href: 'https://github.com/jafernandezm/warrior866' },
                { icon: 'linkedin', label: 'LinkedIn', href: 'https://www.linkedin.com/in/jhon-fer/' },
            ],
            customCss: ['./src/styles/global.css'],
            plugins: [
                starlightLinksValidator({
                    errorOnInvalidHashes: false,
                    errorOnRelativeLinks: false,
                }),
                starlightThemeObsidian({
                    overrideWarnings: true,
                    graphConfig: { visibilityRules: [] },
                }),
            ],
            favicon: './favicon.svg',
            sidebar: [
                {
                    label: '👤 Sobre mí',
                    translations: { en: '👤 About me' },
                    link: '/sobre-mi/',
                },
                {
                    label: '🏆 Certificaciones',
                    translations: { en: '🏆 Certifications' },
                    autogenerate: { directory: 'certificaciones' },
                    collapsed: true,
                },
                {
                    label: '📦 HackTheBox',
                    translations: { en: '📦 HackTheBox' },
                    items: [
                        {
                            label: 'Starting Point',
                            translations: { en: 'Starting Point' },
                            autogenerate: { directory: 'htb/starting-point' },
                            collapsed: true,
                        },
                        {
                            label: 'Fácil',
                            translations: { en: 'Easy' },
                            autogenerate: { directory: 'htb/easy' },
                            collapsed: true,
                        },
                        {
                            label: 'Medio',
                            translations: { en: 'Medium' },
                            autogenerate: { directory: 'htb/medium' },
                            collapsed: true,
                        },
                        {
                            label: 'Difícil',
                            translations: { en: 'Hard' },
                            autogenerate: { directory: 'htb/hard' },
                            collapsed: true,
                        },
                        {
                            label: 'Insano',
                            translations: { en: 'Insane' },
                            autogenerate: { directory: 'htb/insane' },
                            collapsed: true,
                        },
                    ],
                },
                {
                    label: '🚩 HTB Challenges',
                    translations: { en: '🚩 HTB Challenges' },
                    items: [
                        { label: 'Web', autogenerate: { directory: 'challenges/web' }, collapsed: true },
                        { label: 'Crypto', autogenerate: { directory: 'challenges/crypto' }, collapsed: true },
                        {
                            label: 'Reversing',
                            translations: { en: 'Reverse Engineering' },
                            autogenerate: { directory: 'challenges/reversing' },
                            collapsed: true,
                        },
                        { label: 'Pwn', autogenerate: { directory: 'challenges/pwn' }, collapsed: true },
                        {
                            label: 'Forensics',
                            translations: { en: 'Forensics' },
                            autogenerate: { directory: 'challenges/forensics' },
                            collapsed: true,
                        },
                        { label: 'Misc', autogenerate: { directory: 'challenges/misc' }, collapsed: true },
                    ],
                },
                {
                    label: '🎯 OffSec',
                    translations: { en: '🎯 OffSec' },
                    items: [
                        { label: 'OSCP', autogenerate: { directory: 'offsec/oscp' }, collapsed: true },
                        { label: 'PEN-200', autogenerate: { directory: 'offsec/pen-200' }, collapsed: true },
                        {
                            label: 'Proving Grounds',
                            translations: { en: 'Proving Grounds' },
                            autogenerate: { directory: 'offsec/proving-grounds' },
                            collapsed: true,
                        },
                    ],
                },
            ],
            components: {
                Head: './src/overrides/Head.astro',
            },
        }),
    ],
    devToolbar: { enabled: false },
});