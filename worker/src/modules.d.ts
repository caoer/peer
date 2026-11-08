// wrangler.jsonc `rules`: an .html import is the file's text.
declare module "*.html" {
  const text: string;
  export default text;
}
