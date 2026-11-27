// Throwaway design mockup of the web console (sample data, no API). Served only by `vite` at /mockup.html.
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "@fontsource/chakra-petch/latin-400.css";
import "@fontsource/chakra-petch/latin-500.css";
import "@fontsource/chakra-petch/latin-600.css";
import "@fontsource/chakra-petch/latin-700.css";
import "@fontsource/azeret-mono/latin-400.css";
import "@fontsource/azeret-mono/latin-500.css";
import "../app.css";
import "./legacy.css";
import "./console.css";
import { Console } from "./Console";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Console />
  </StrictMode>,
);
