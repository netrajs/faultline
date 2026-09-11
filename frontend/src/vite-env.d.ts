/// <reference types="vite/client" />

interface ImportMetaEnv {
  /** Path or origin the browser calls for the API. Defaults to '/api'. */
  readonly VITE_API_BASE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
