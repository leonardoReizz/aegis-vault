import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import "./index.css";

// Apply saved theme or default to dark
const savedTheme = localStorage.getItem("pass-theme") || "dark";
document.documentElement.classList.toggle("dark", savedTheme === "dark");

function dismissSplash() {
  const splash = document.getElementById("splash");
  if (splash) {
    splash.classList.add("fade-out");
    splash.addEventListener("transitionend", () => splash.remove(), { once: true });
  }
}

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>
    <App onReady={dismissSplash} />
  </React.StrictMode>,
);
