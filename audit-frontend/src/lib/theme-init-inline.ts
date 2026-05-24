import {
  AUDIT_THEME_DEFAULT,
  AUDIT_THEME_ENABLE_SYSTEM,
  AUDIT_THEME_STORAGE_KEY,
} from "@/lib/theme-config";

/**
 * Runs synchronously as the first child of `<body>` so the first paint matches
 * the user’s saved theme (avoids a light → dark flash on hard refresh).
 * Mirrors next-themes + adds `awsui-dark-mode` on `body` for Cloudscape.
 */
export const THEME_INIT_INLINE_SCRIPT = `!function(){try{var k=${JSON.stringify(AUDIT_THEME_STORAGE_KEY)};var def=${JSON.stringify(AUDIT_THEME_DEFAULT)};var sys=${AUDIT_THEME_ENABLE_SYSTEM};var r=document.documentElement;var b=document.body;var s=null;try{s=localStorage.getItem(k);}catch(e1){}var t=s||def;if(sys&&t==="system"){t=window.matchMedia("(prefers-color-scheme: dark)").matches?"dark":"light";}if(t!=="light"&&t!=="dark"){t=def;}r.classList.remove("light","dark");r.classList.add(t);r.style.colorScheme=t==="dark"?"dark":"light";if(t==="dark"){b.classList.add("awsui-dark-mode");}else{b.classList.remove("awsui-dark-mode");}}catch(e2){var h=document.documentElement;var bd=document.body;h.classList.remove("light","dark");h.classList.add("dark");h.style.colorScheme="dark";bd.classList.add("awsui-dark-mode");}}();`;
