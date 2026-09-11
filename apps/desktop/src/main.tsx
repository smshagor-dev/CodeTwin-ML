import React from "react";
import ReactDOM from "react-dom/client";
import { DesktopRoot } from "./DesktopRoot";
import "./styles.css";

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode><DesktopRoot /></React.StrictMode>,
);
