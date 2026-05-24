import {
  AUDIT_THEME_DEFAULT,
  AUDIT_THEME_ENABLE_SYSTEM,
  AUDIT_THEME_STORAGE_KEY,
} from "@/lib/theme-config";

/**
 * When embedding string literals into inline `<script>` source, HTML and JS
 * parsers can be tripped by `</script>`, `<`, `>`, and Unicode line separators.
 * `JSON.stringify` does not guarantee HTML-safe script embedding on its own;
 * this helper keeps the serialized literal safe for `dangerouslySetInnerHTML`.
 */
function escapeJsonForInlineScriptEmbedding(serialized: string): string {
  return serialized.replace(/[<>\u2028\u2029]/g, (char) => {
    switch (char) {
      case "<":
        return String.raw`\u003C`;
      case ">":
        return String.raw`\u003E`;
      case "\u2028":
        return String.raw`\u2028`;
      case "\u2029":
        return String.raw`\u2029`;
      default:
        return char;
    }
  });
}

/**
 * Runs synchronously as the first child of `<body>` so the first paint matches
 * the user’s saved theme (avoids a light → dark flash on hard refresh).
 * Mirrors next-themes + adds `awsui-dark-mode` on `body` for Cloudscape.
 */
export const THEME_INIT_INLINE_SCRIPT = `!function(){try{var k=${escapeJsonForInlineScriptEmbedding(JSON.stringify(AUDIT_THEME_STORAGE_KEY))};var def=${escapeJsonForInlineScriptEmbedding(JSON.stringify(AUDIT_THEME_DEFAULT))};var sys=${AUDIT_THEME_ENABLE_SYSTEM};var r=document.documentElement;var b=document.body;var s=null;try{s=localStorage.getItem(k);}catch(e1){}var t=s||def;if(sys&&t==="system"){t=window.matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light";}if(t!=="light"&&t!=="dark"){t=def;}r.classList.remove("light","dark");r.classList.add(t);r.style.colorScheme=t==="dark"?"dark":"light";if(t==="dark"){b.classList.add("awsui-dark-mode");}else{b.classList.remove("awsui-dark-mode");}}catch(e2){var h=document.documentElement;var bd=document.body;h.classList.remove("light","dark");h.classList.add("dark");h.style.colorScheme="dark";bd.classList.add("awsui-dark-mode");}}();`;
