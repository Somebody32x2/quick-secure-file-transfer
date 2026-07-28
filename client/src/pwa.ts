/**
 * Progressive web app wiring: install prompt, offline readiness, and updates.
 *
 * Service workers require a secure context, so on the plain-HTTP LAN origins
 * this app deliberately supports, none of this is available. That is a browser
 * rule, not a bug - the transfer features work regardless, and the UI says so
 * rather than showing a dead install button.
 */

interface BeforeInstallPromptEvent extends Event {
  prompt(): Promise<void>;
  userChoice: Promise<{ outcome: 'accepted' | 'dismissed' }>;
}

let deferredPrompt: BeforeInstallPromptEvent | null = null;
let updateReady: ServiceWorkerRegistration | null = null;

const listeners = new Set<() => void>();
const notify = () => listeners.forEach((fn) => fn());

/** Re-render whatever is showing install/update state. */
export function onPwaChange(fn: () => void): void {
  listeners.add(fn);
}

export function isStandalone(): boolean {
  try {
    return matchMedia('(display-mode: standalone)').matches
      || matchMedia('(display-mode: minimal-ui)').matches
      // iOS Safari predates display-mode and uses a non-standard flag.
      || (navigator as unknown as { standalone?: boolean }).standalone === true;
  } catch {
    return false;
  }
}

export function serviceWorkerSupported(): boolean {
  return 'serviceWorker' in navigator && globalThis.isSecureContext === true;
}

export function canInstall(): boolean {
  return deferredPrompt !== null;
}

export function hasUpdate(): boolean {
  return updateReady !== null;
}

/** iOS never fires beforeinstallprompt; installing there is a manual gesture. */
export function isIosSafari(): boolean {
  const ua = navigator.userAgent;
  const iOS = /iPad|iPhone|iPod/.test(ua)
    // iPadOS 13+ reports as a Mac, distinguished by touch support.
    || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);
  return iOS && /Safari/.test(ua) && !/CriOS|FxiOS|EdgiOS/.test(ua);
}

export async function promptInstall(): Promise<'accepted' | 'dismissed' | 'unavailable'> {
  if (!deferredPrompt) return 'unavailable';
  const prompt = deferredPrompt;
  // A prompt event can only be used once.
  deferredPrompt = null;
  notify();
  await prompt.prompt();
  const { outcome } = await prompt.userChoice;
  return outcome;
}

/** Activate the waiting worker, then reload onto the new code. */
export function applyUpdate(): void {
  const registration = updateReady;
  if (!registration?.waiting) return;
  let reloaded = false;
  navigator.serviceWorker.addEventListener('controllerchange', () => {
    if (reloaded) return;
    reloaded = true;
    location.reload();
  });
  registration.waiting.postMessage({ type: 'SKIP_WAITING' });
}

export function initPwa(): void {
  window.addEventListener('beforeinstallprompt', (event) => {
    // Suppress the browser's own mini-infobar so the app can place the offer
    // somewhere it makes sense.
    event.preventDefault();
    deferredPrompt = event as BeforeInstallPromptEvent;
    notify();
  });

  window.addEventListener('appinstalled', () => {
    deferredPrompt = null;
    notify();
  });

  if (!serviceWorkerSupported()) return;

  window.addEventListener('load', () => {
    navigator.serviceWorker.register('/sw.js', { scope: '/' }).then((registration) => {
      const track = (worker: ServiceWorker | null) => {
        if (!worker) return;
        worker.addEventListener('statechange', () => {
          // "installed" with an existing controller means an update is waiting.
          if (worker.state === 'installed' && navigator.serviceWorker.controller) {
            updateReady = registration;
            notify();
          }
        });
      };

      if (registration.waiting && navigator.serviceWorker.controller) {
        updateReady = registration;
        notify();
      }
      track(registration.installing);
      registration.addEventListener('updatefound', () => track(registration.installing));
    }).catch(() => {
      // Registration failing costs nothing but offline support.
    });
  });
}
