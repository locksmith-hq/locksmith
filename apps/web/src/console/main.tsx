// The Locksmith web console. This is the product's UI and where its work continues; it runs on sample data
// until it is connected to the control plane. Served by `vite` at /.
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "../app.css";
import "./kit-compat.css";
import "./legacy.css";
import "./console.css";
import { Console } from "./Console";

// Paid pages register themselves when a build has them. This folder is git-ignored and empty in the open build.
import.meta.glob("./paid/*.tsx", { eager: true });

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <Console />
  </StrictMode>,
);
