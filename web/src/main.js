import { mount } from 'svelte';
import './app.css';
import App from './App.svelte';

const app = mount(App, {
  target: document.getElementById('app'),
});

// Register the service worker only in production, after the window has loaded,
// so the M0 app shell is cached for offline/repeated visits. BASE_URL is './'
// (see vite.config.js base), which resolves correctly under /cawala/ on Pages.
if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker
      .register(import.meta.env.BASE_URL + 'sw.js')
      .catch((err) => console.warn('service worker registration failed', err));
  });
}

export default app;
