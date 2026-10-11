import { render } from "solid-js/web";
import App from "./App";
import { loadSession } from "./auth/session";
import { browserLocales, resolveLocale, setLocale, storedLocale } from "./i18n";
import { loadLanguages } from "./i18n/remote";
import "./app/styles/tokens.css";
import "./app/styles/fonts.css";
import "./app/styles/design.css";
import "./app/styles/app.css";

async function start(): Promise<void> {
  // Development with the mock API (npm run dev:mock). The condition is replaced at build
  // time, so production bundles contain neither the handlers nor the worker.
  if (import.meta.env.DEV && import.meta.env.VITE_TENKO_MOCK === "1") {
    const { startMockWorker } = await import("./api/mock/browser");
    await startMockWorker();
  }
  // The language before anyone signs in; the session may change it (API-08).
  await loadLanguages();
  await setLocale(resolveLocale({ stored: storedLocale(), browser: browserLocales() }));

  const root = document.getElementById("root");
  if (!root) throw new Error("Root element #root not found");
  render(() => <App />, root);
  void loadSession();
}

void start();
