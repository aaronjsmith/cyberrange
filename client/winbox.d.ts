declare module 'winbox/src/js/winbox.js' {
  interface WinBoxOptions {
    title?: string;
    width?: string | number;
    height?: string | number;
    x?: string | number;
    y?: string | number;
    background?: string;
    html?: string;
    class?: string | string[];
    mount?: HTMLElement;
  }

  export default class WinBox {
    constructor(options?: WinBoxOptions | string, options2?: WinBoxOptions);
    body: HTMLElement;
    mount(element: HTMLElement): this;
  }
}
