// TypeScript declarations for WASM modules
// Cloudflare Workers bundle WASM files as WebAssembly.Module at build time

declare module '*.wasm' {
  const wasmModule: WebAssembly.Module;
  export default wasmModule;
}
