/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_DESIGN_ROUTE?: string;
  readonly VITE_REPORT?: string;
  readonly VITE_DEMO?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
