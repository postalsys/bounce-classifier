// The bundled model directory, as a URL. It sits at the package root, so its location depends on
// where the compiled module is: scripts/build.js replaces this file in dist/esm and dist/cjs with
// one that resolves it from there. This version serves the sources (the tests run them through tsx).
export const defaultModelUrl: string = new URL('../model', import.meta.url).href;
