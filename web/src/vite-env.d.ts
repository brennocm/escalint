/// <reference types="vite/client" />

interface ImportMetaEnv {
  readonly VITE_DESIGN_ROUTE?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
