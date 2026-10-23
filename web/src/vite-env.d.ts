/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_DESIGN_ROUTE?: string;
  readonly VITE_REPORT?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
