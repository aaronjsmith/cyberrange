declare module '*.css?inline' {
  const css: string;
  export default css;
}

declare module '*.jpg' {
  const src: string;
  export default src;
}

declare module '*.png' {
  const src: string;
  export default src;
}

declare module '*.svg?raw' {
  const svg: string;
  export default svg;
}
