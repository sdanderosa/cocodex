import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { installApiAuthFetch, resolveManagedApiBase } from "./api";
import { LanguageProvider } from "./i18n";
import "./styles.css";

const configuredApiBase = import.meta.env.VITE_API_BASE
  || (typeof window !== "undefined" && "__TAURI_INTERNALS__" in window
    ? "http://127.0.0.1:10101"
    : "");

installApiAuthFetch();

function render(apiBase: string): void {
  ReactDOM.createRoot(document.getElementById("root")!).render(
    <React.StrictMode>
      <LanguageProvider>
        <App apiBase={apiBase} />
      </LanguageProvider>
    </React.StrictMode>,
  );
}

void resolveManagedApiBase(configuredApiBase).then(render, () => render(configuredApiBase));
