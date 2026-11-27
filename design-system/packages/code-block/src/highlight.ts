// Syntax colours for CodeBlock, from Shiki. Not part of shadcn's CodeBlock.
// The highlighter and each language's grammar are loaded on first use, so a page that shows no highlighted
// code pays nothing, and one that shows bash pays for bash only. Colours are CSS variables (`--code-*`, set
// in @locksmith-hq/styles), so one theme serves light and dark.
import { useEffect, useState } from "react";
import { createCssVariablesTheme, createHighlighterCore } from "shiki/core";
import type { HighlighterCore, ThemedToken } from "shiki/core";
import { createJavaScriptRegexEngine } from "shiki/engine/javascript";
import { bundledLanguages } from "shiki/langs";

const theme = createCssVariablesTheme({ name: "locksmith", variablePrefix: "--code-", fontStyle: true });
let highlighter: Promise<HighlighterCore> | undefined;

async function tokenize(code: string, language: string): Promise<ThemedToken[][] | null> {
  const load = bundledLanguages[language as keyof typeof bundledLanguages];
  if (!load) return null; // a language Shiki does not know stays plain
  highlighter ??= createHighlighterCore({ themes: [theme], langs: [], engine: createJavaScriptRegexEngine() });
  const h = await highlighter;
  if (!h.getLoadedLanguages().includes(language)) await h.loadLanguage(load);
  return h.codeToTokensBase(code, { lang: language, theme: "locksmith" });
}

// The code as lines of coloured tokens, or null while the grammar loads (and when there is no language, or
// it failed to load): the caller shows the plain text meanwhile, which takes the same space.
export function useHighlight(code: unknown, language: string | undefined): ThemedToken[][] | null {
  const [done, setDone] = useState<{ code: string; language: string; lines: ThemedToken[][] } | null>(null);
  const text = typeof code === "string" ? code.replace(/\n$/, "") : null;
  useEffect(() => {
    if (text === null || !language) return;
    let live = true;
    tokenize(text, language)
      .then((lines) => live && lines && setDone({ code: text, language, lines }))
      .catch(() => {});
    return () => {
      live = false;
    };
  }, [text, language]);
  return done && done.code === text && done.language === language ? done.lines : null;
}
