/** Minimal DOM helpers. No framework: less to audit, smaller bundle. */

type Attrs = Record<string, string | number | boolean | ((e: Event) => void) | undefined>;
type Child = Node | string | null | undefined | false;

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attrs: Attrs = {},
  ...children: Child[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === false) continue;
    if (key.startsWith('on') && typeof value === 'function') {
      node.addEventListener(key.slice(2).toLowerCase(), value as EventListener);
    } else if (key === 'class') {
      node.className = String(value);
    } else if (key === 'text') {
      node.textContent = String(value);
    } else if (key === 'html') {
      // Only ever called with literals from this codebase, never with peer data.
      node.innerHTML = String(value);
    } else if (value === true) {
      node.setAttribute(key, '');
    } else {
      node.setAttribute(key, String(value));
    }
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
}

export function clear(node: HTMLElement): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function mount(root: HTMLElement, ...children: Child[]): void {
  clear(root);
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    root.append(typeof child === 'string' ? document.createTextNode(child) : child);
  }
}

/** Announce a message to screen readers without moving focus. */
export function announce(message: string): void {
  let region = document.getElementById('qsft-live');
  if (!region) {
    region = el('div', { id: 'qsft-live', class: 'sr-only', 'aria-live': 'polite', role: 'status' });
    document.body.append(region);
  }
  region.textContent = message;
}
