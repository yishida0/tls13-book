import fs from "node:fs";
import path from "node:path";
import type { MarkdownRenderer } from "vitepress";

const escapeAttr = (s: string) =>
  s.replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;");

export function inlineSvg(md: MarkdownRenderer) {
  const defaultImage = md.renderer.rules.image!;

  md.renderer.rules.image = (tokens, idx, options, env, self) => {
    const token = tokens[idx];
    const m = (token.attrGet("src") ?? "").match(/^(\.{1,2}\/[^?#]+\.svg)$/);
    if (!m || !env.path) return defaultImage(tokens, idx, options, env, self);

    const file = path.resolve(path.dirname(env.path), m[1]);
    const alt = self.renderInlineAsText(token.children ?? [], options, env);
    const prefix = path
      .relative(process.cwd(), file)
      .replace(/\.svg$/, "")
      .replace(/[^\w-]/g, "-");

    const svg = fs
      .readFileSync(file, "utf8")
      .replace(/<\?xml[\s\S]*?\?>|<!--[\s\S]*?-->/g, "")
      .replace(/\bid="([^"]+)"/g, `id="${prefix}-$1"`)
      .replace(/url\(#([^)]+)\)/g, `url(#${prefix}-$1)`)
      .replace(/href="#([^"]+)"/g, `href="#${prefix}-$1"`)
      .replace(
        /<svg\b/,
        `<svg class="inline-svg" role="img" aria-label="${escapeAttr(alt)}"`,
      )
      .trim();

    return svg;
  };
}
