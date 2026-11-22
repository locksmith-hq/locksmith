// Throwaway design mockup of the web console (sample data, no API). Served only by `vite` at /mockup.html.
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/figtree/latin-400.css";
import "@fontsource/figtree/latin-500.css";
import "@fontsource/figtree/latin-600.css";
import "@fontsource/figtree/latin-700.css";
import "@fontsource/jetbrains-mono/latin-400.css";
import "@fontsource/jetbrains-mono/latin-500.css";
import "@fontsource/unbounded/latin-500.css";
import "@locksmith/ui/tokens.css";
import "../../../desktop/src/styles.css";
import "@locksmith/ui/kit.css";
import "./console.css";
import { Console } from "./Console";

createRoot(document.getElementById("root")!).render(<StrictMode><Console /></StrictMode>);
