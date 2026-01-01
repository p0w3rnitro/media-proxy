/**
 * Flixer Stream Proxy
 * 
 * Handles Flixer API requests with WASM-based encryption/decryption.
 * The WASM module generates keys and decrypts API responses.
 * 
 * Flow:
 *   Client -> Cloudflare Worker -> Flixer API -> Decrypt -> Return m3u8 URL
 * 
 * Routes:
 *   GET /flixer/extract?tmdbId=<id>&type=<movie|tv>&season=<n>&episode=<n>&server=<name>
 *   GET /flixer/health - Health check
 * 
 * Key discoveries from cracking:
 *   - The `bW90aGFmYWth` header BLOCKS requests when present - must NOT send it
 *   - The `Origin` header should NOT be sent
 *   - The `sec-fetch-*` headers should NOT be sent
 *   - A "warm-up" request without X-Server header is needed before the actual request
 * 
 * IMPORTANT: WASM is bundled at build time via wrangler, not fetched at runtime.
 * This avoids the "Wasm code generation disallowed by embedder" error.
 */

import { createLogger, type LogLevel } from './logger';
// Import WASM module - bundled at build time by wrangler
import FLIXER_WASM from './flixer.wasm';

export interface Env {
  LOG_LEVEL?: string;
}

const FLIXER_API_BASE = 'https://plsdontscrapemelove.flixer.sh';

// CORS headers
function corsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  };
}

function jsonResponse(data: object, status: number): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'Content-Type': 'application/json', ...corsHeaders() },
  });
}

// Server name to display name mapping (NATO alphabet to mythology)
const SERVER_NAMES: Record<string, string> = {
  alpha: 'Ares',
  bravo: 'Balder',
  charlie: 'Circe',
  delta: 'Dionysus',
  echo: 'Eros',
  foxtrot: 'Freya',
};

// NATO phonetic alphabet order for server priority
const NATO_ORDER = [
  'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot', 'golf', 'hotel',
  'india', 'juliet', 'kilo', 'lima', 'mike', 'november', 'oscar', 'papa',
  'quebec', 'romeo', 'sierra', 'tango', 'uniform', 'victor', 'whiskey',
  'xray', 'yankee', 'zulu'
];

/**
 * WASM Loader for Flixer decryption
 * Mocks browser APIs required by the WASM module
 */
class FlixerWasmLoader {
  private wasm: any = null;
  private heap: any[] = new Array(128).fill(undefined);
  private heap_next: number;
  private WASM_VECTOR_LEN = 0;
  private cachedUint8ArrayMemory0: Uint8Array | null = null;
  private cachedDataViewMemory0: DataView | null = null;
  private cachedTextDecoder = new TextDecoder('utf-8', { ignoreBOM: true, fatal: true });
  private cachedTextEncoder = new TextEncoder();
  
  // Browser fingerprint values
  private sessionId: string;
  private timestamp: number;
  private randomSeed: number;
  private screenWidth = 1920;
  private screenHeight = 1080;
  private colorDepth = 24;
  private platform = 'Win32';
  private language = 'en-US';
  private userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36';
  private timezoneOffset: number;

  constructor(opts: { sessionId?: string; timestamp?: number } = {}) {
    this.heap.push(undefined, null, true, false);
    this.heap_next = this.heap.length;
    this.sessionId = opts.sessionId || crypto.randomUUID().replace(/-/g, '');
    this.timestamp = opts.timestamp || (Date.now() - 5000);
    this.randomSeed = Math.random();
    this.timezoneOffset = new Date().getTimezoneOffset();
  }

  private getObject(idx: number) { return this.heap[idx]; }
  
  private addHeapObject(obj: any): number {
    if (this.heap_next === this.heap.length) this.heap.push(this.heap.length + 1);
    const idx = this.heap_next;
    this.heap_next = this.heap[idx] as number;
    this.heap[idx] = obj;
    return idx;
  }
  
  private dropObject(idx: number) {
    if (idx < 132) return;
    this.heap[idx] = this.heap_next;
    this.heap_next = idx;
  }
  
  private takeObject(idx: number) {
    const ret = this.getObject(idx);
    this.dropObject(idx);
    return ret;
  }

  private getUint8ArrayMemory0(): Uint8Array {
    if (!this.cachedUint8ArrayMemory0 || this.cachedUint8ArrayMemory0.byteLength === 0) {
      this.cachedUint8ArrayMemory0 = new Uint8Array(this.wasm.memory.buffer);
    }
    return this.cachedUint8ArrayMemory0;
  }

  private getDataViewMemory0(): DataView {
    if (!this.cachedDataViewMemory0 || this.cachedDataViewMemory0.buffer !== this.wasm.memory.buffer) {
      this.cachedDataViewMemory0 = new DataView(this.wasm.memory.buffer);
    }
    return this.cachedDataViewMemory0;
  }

  private getStringFromWasm0(ptr: number, len: number): string {
    return this.cachedTextDecoder.decode(this.getUint8ArrayMemory0().subarray(ptr >>> 0, (ptr >>> 0) + len));
  }

  private passStringToWasm0(arg: string, malloc: (len: number, align: number) => number): number {
    const buf = this.cachedTextEncoder.encode(arg);
    const ptr = malloc(buf.length, 1) >>> 0;
    this.getUint8ArrayMemory0().subarray(ptr, ptr + buf.length).set(buf);
    this.WASM_VECTOR_LEN = buf.length;
    return ptr;
  }

  private isLikeNone(x: any): boolean { return x === undefined || x === null; }

  private handleError(f: Function, args: any[]) {
    try { return f.apply(this, args); }
    catch (e) { this.wasm.__wbindgen_export_0(this.addHeapObject(e)); }
  }

  private createMockCanvas() {
    const canvasData = `canvas-fp-${this.screenWidth}x${this.screenHeight}-${this.colorDepth}-${this.platform}-${this.language}`;
    const dataUrl = 'data:image/png;base64,' + btoa(canvasData);
    
    const ctx = {
      _font: '14px Arial',
      _textBaseline: 'alphabetic',
      fillText: function() {},
      get font() { return this._font; },
      set font(v: string) { this._font = v; },
      get textBaseline() { return this._textBaseline; },
      set textBaseline(v: string) { this._textBaseline = v; },
    };
    
    return {
      _width: 200,
      _height: 50,
      get width() { return this._width; },
      set width(v: number) { this._width = v; },
      get height() { return this._height; },
      set height(v: number) { this._height = v; },
      getContext: (type: string) => type === '2d' ? ctx : null,
      toDataURL: () => dataUrl,
    };
  }

  private buildImports() {
    const self = this;
    
    // Mock DOM elements
    const mockBody = { 
      appendChild: () => {},
      tagName: 'BODY',
      nodeName: 'BODY',
      nodeType: 1,
      innerHTML: '',
      outerHTML: '<body></body>',
      parentNode: null,
      parentElement: null,
      children: [],
      childNodes: [],
      firstChild: null,
      lastChild: null,
      nextSibling: null,
      previousSibling: null,
      ownerDocument: null,
      style: {},
      className: '',
      classList: { add: () => {}, remove: () => {}, contains: () => false, toggle: () => {} },
      getAttribute: () => null,
      setAttribute: () => {},
      removeAttribute: () => {},
      hasAttribute: () => false,
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => true,
      getBoundingClientRect: () => ({ top: 0, left: 0, bottom: 0, right: 0, width: 0, height: 0 }),
      scrollTop: 0,
      scrollLeft: 0,
      scrollWidth: 0,
      scrollHeight: 0,
      clientWidth: this.screenWidth,
      clientHeight: this.screenHeight,
      offsetWidth: this.screenWidth,
      offsetHeight: this.screenHeight,
      offsetTop: 0,
      offsetLeft: 0,
    };

    const createCollection = (elements: any[]) => {
      const collection: any = {
        length: elements.length,
        item: (i: number) => elements[i] || null,
        namedItem: () => null,
        [Symbol.iterator]: function* () { for (const e of elements) yield e; }
      };
      elements.forEach((el, i) => { collection[i] = el; });
      return new Proxy(collection, {
        get(target, prop) {
          if (typeof prop === 'string' && !isNaN(parseInt(prop))) {
            return target[parseInt(prop)];
          }
          return target[prop];
        }
      });
    };
    
    const trackedBody = new Proxy(mockBody, {
      get(target: any, prop) { return target[prop]; },
      set(target: any, prop, value) { target[prop] = value; return true; }
    });
    
    const doc = { 
      createElement: (t: string) => t === 'canvas' ? self.createMockCanvas() : {},
      getElementsByTagName: (t: string) => t === 'body' ? createCollection([trackedBody]) : createCollection([]),
      body: trackedBody,
    };
    
    const ls = { 
      getItem: (k: string) => k === 'tmdb_session_id' ? self.sessionId : null,
      setItem: () => {},
    };
    
    const nav = { platform: this.platform, language: this.language, userAgent: this.userAgent };
    const scr = { width: this.screenWidth, height: this.screenHeight, colorDepth: this.colorDepth };
    const perf = { now: () => Date.now() - this.timestamp };
    const win = { document: doc, localStorage: ls, navigator: nav, screen: scr, performance: perf };
    
    const i: any = { wbg: {} };

    // Function calls
    i.wbg.__wbg_call_672a4d21634d4a24 = function() { 
      return self.handleError((a: number, b: number) => self.addHeapObject(self.getObject(a).call(self.getObject(b))), arguments as any); 
    };
    i.wbg.__wbg_call_7cccdd69e0791ae2 = function() { 
      return self.handleError((a: number, b: number, c: number) => self.addHeapObject(self.getObject(a).call(self.getObject(b), self.getObject(c))), arguments as any); 
    };

    // Screen
    i.wbg.__wbg_colorDepth_59677c81c61d599a = function() { 
      return self.handleError((a: number) => self.getObject(a).colorDepth, arguments as any);
    };
    i.wbg.__wbg_height_614ba187d8cae9ca = function() {
      return self.handleError((a: number) => self.getObject(a).height, arguments as any);
    };
    i.wbg.__wbg_width_679079836447b4b7 = function() {
      return self.handleError((a: number) => self.getObject(a).width, arguments as any);
    };
    i.wbg.__wbg_screen_8edf8699f70d98bc = function() {
      return self.handleError((a: number) => {
        const w = self.getObject(a);
        return self.addHeapObject(w ? w.screen : scr);
      }, arguments as any);
    };
    
    // Document
    i.wbg.__wbg_document_d249400bd7bd996d = (a: number) => { 
      const w = self.getObject(a);
      const d = w ? w.document : null;
      if (d) {
        const trackedDoc = new Proxy(d, { get(target: any, prop) { return target[prop]; } });
        return self.addHeapObject(trackedDoc);
      }
      return 0;
    };
    i.wbg.__wbg_createElement_8c9931a732ee2fea = function() { 
      return self.handleError((a: number, b: number, c: number) => self.addHeapObject(doc.createElement(self.getStringFromWasm0(b, c))), arguments as any);
    };
    i.wbg.__wbg_getElementsByTagName_f03d41ce466561e8 = (a: number, b: number, c: number) => self.addHeapObject(doc.getElementsByTagName(self.getStringFromWasm0(b, c)));
    
    // Canvas
    i.wbg.__wbg_getContext_e9cf379449413580 = function() { 
      return self.handleError((a: number, b: number, c: number) => { 
        const r = self.getObject(a).getContext(self.getStringFromWasm0(b, c)); 
        return self.isLikeNone(r) ? 0 : self.addHeapObject(r); 
      }, arguments as any);
    };
    i.wbg.__wbg_fillText_2a0055d8531355d1 = function() { 
      return self.handleError((a: number, b: number, c: number, d: number, e: number) => self.getObject(a).fillText(self.getStringFromWasm0(b, c), d, e), arguments as any);
    };
    i.wbg.__wbg_setfont_42a163ef83420b93 = (a: number, b: number, c: number) => { self.getObject(a).font = self.getStringFromWasm0(b, c); };
    i.wbg.__wbg_settextBaseline_c28d2a6aa4ff9d9d = (a: number, b: number, c: number) => { self.getObject(a).textBaseline = self.getStringFromWasm0(b, c); };
    i.wbg.__wbg_setheight_da683a33fa99843c = (a: number, b: number) => { self.getObject(a).height = b >>> 0; };
    i.wbg.__wbg_setwidth_c5fed9f5e7f0b406 = (a: number, b: number) => { self.getObject(a).width = b >>> 0; };
    i.wbg.__wbg_toDataURL_eaec332e848fe935 = function() { 
      return self.handleError((a: number, b: number) => { 
        const r = self.getObject(b).toDataURL(); 
        const p = self.passStringToWasm0(r, self.wasm.__wbindgen_export_1); 
        self.getDataViewMemory0().setInt32(a + 4, self.WASM_VECTOR_LEN, true); 
        self.getDataViewMemory0().setInt32(a, p, true); 
      }, arguments as any);
    };
    i.wbg.__wbg_instanceof_CanvasRenderingContext2d_df82a4d3437bf1cc = () => 1;
    i.wbg.__wbg_instanceof_HtmlCanvasElement_2ea67072a7624ac5 = () => 1;
    i.wbg.__wbg_instanceof_Window_def73ea0955fc569 = () => 1;

    // LocalStorage
    i.wbg.__wbg_localStorage_1406c99c39728187 = function() { 
      return self.handleError((a: number) => {
        const w = self.getObject(a);
        const storage = w ? w.localStorage : ls;
        return self.isLikeNone(storage) ? 0 : self.addHeapObject(storage);
      }, arguments as any); 
    };
    i.wbg.__wbg_getItem_17f98dee3b43fa7e = function() { 
      return self.handleError((a: number, b: number, c: number, d: number) => { 
        const r = self.getObject(b).getItem(self.getStringFromWasm0(c, d)); 
        const p = self.isLikeNone(r) ? 0 : self.passStringToWasm0(r, self.wasm.__wbindgen_export_1); 
        self.getDataViewMemory0().setInt32(a + 4, self.WASM_VECTOR_LEN, true); 
        self.getDataViewMemory0().setInt32(a, p, true); 
      }, arguments as any); 
    };
    i.wbg.__wbg_setItem_212ecc915942ab0a = function() { 
      return self.handleError((a: number, b: number, c: number, d: number, e: number) => {
        self.getObject(a).setItem(self.getStringFromWasm0(b, c), self.getStringFromWasm0(d, e));
      }, arguments as any); 
    };
    
    // Navigator
    i.wbg.__wbg_navigator_1577371c070c8947 = (a: number) => { 
      const w = self.getObject(a);
      return self.addHeapObject(w ? w.navigator : nav); 
    };
    i.wbg.__wbg_language_d871ec78ee8eec62 = (a: number, b: number) => { 
      const r = self.getObject(b).language; 
      const p = self.isLikeNone(r) ? 0 : self.passStringToWasm0(r, self.wasm.__wbindgen_export_1); 
      self.getDataViewMemory0().setInt32(a + 4, self.WASM_VECTOR_LEN, true); 
      self.getDataViewMemory0().setInt32(a, p, true); 
    };
    i.wbg.__wbg_platform_faf02c487289f206 = function() { 
      return self.handleError((a: number, b: number) => { 
        const r = self.getObject(b).platform; 
        const p = self.passStringToWasm0(r, self.wasm.__wbindgen_export_1); 
        self.getDataViewMemory0().setInt32(a + 4, self.WASM_VECTOR_LEN, true); 
        self.getDataViewMemory0().setInt32(a, p, true); 
      }, arguments as any); 
    };
    i.wbg.__wbg_userAgent_12e9d8e62297563f = function() { 
      return self.handleError((a: number, b: number) => { 
        const r = self.getObject(b).userAgent; 
        const p = self.passStringToWasm0(r, self.wasm.__wbindgen_export_1); 
        self.getDataViewMemory0().setInt32(a + 4, self.WASM_VECTOR_LEN, true); 
        self.getDataViewMemory0().setInt32(a, p, true); 
      }, arguments as any); 
    };

    // Date/Time
    i.wbg.__wbg_new0_f788a2397c7ca929 = () => self.addHeapObject(new Date(self.timestamp));
    i.wbg.__wbg_now_807e54c39636c349 = () => self.timestamp;
    i.wbg.__wbg_getTimezoneOffset_6b5752021c499c47 = () => self.timezoneOffset;
    i.wbg.__wbg_performance_c185c0cdc2766575 = (a: number) => {
      const w = self.getObject(a);
      const p = w ? w.performance : perf;
      return self.isLikeNone(p) ? 0 : self.addHeapObject(p);
    };
    i.wbg.__wbg_now_d18023d54d4e5500 = (a: number) => self.getObject(a).now();
    i.wbg.__wbg_random_3ad904d98382defe = () => self.randomSeed;
    
    // Utility
    i.wbg.__wbg_length_347907d14a9ed873 = (a: number) => self.getObject(a).length;
    i.wbg.__wbg_new_23a2665fac83c611 = (a: number, b: number) => { 
      try { 
        var s: any = { a, b }; 
        var cb = (x: any, y: any) => { 
          const t = s.a; s.a = 0; 
          try { return self.wasm.__wbindgen_export_6(t, s.b, self.addHeapObject(x), self.addHeapObject(y)); } 
          finally { s.a = t; } 
        }; 
        return self.addHeapObject(new Promise(cb)); 
      } finally { s.a = s.b = 0; } 
    };
    i.wbg.__wbg_resolve_4851785c9c5f573d = (a: number) => self.addHeapObject(Promise.resolve(self.getObject(a)));
    i.wbg.__wbg_reject_b3fcf99063186ff7 = (a: number) => self.addHeapObject(Promise.reject(self.getObject(a)));
    i.wbg.__wbg_then_44b73946d2fb3e7d = (a: number, b: number) => self.addHeapObject(self.getObject(a).then(self.getObject(b)));
    i.wbg.__wbg_newnoargs_105ed471475aaf50 = (a: number, b: number) => self.addHeapObject(new Function(self.getStringFromWasm0(a, b)));
    
    // Global accessors
    i.wbg.__wbg_static_accessor_GLOBAL_88a902d13a557d07 = () => 0;
    i.wbg.__wbg_static_accessor_GLOBAL_THIS_56578be7e9f832b0 = () => self.addHeapObject(globalThis);
    i.wbg.__wbg_static_accessor_SELF_37c5d418e4bf5819 = () => self.addHeapObject(win);
    i.wbg.__wbg_static_accessor_WINDOW_5de37043a91a9c40 = () => self.addHeapObject(win);
    
    // Microtask
    i.wbg.__wbg_queueMicrotask_97d92b4fcc8a61c5 = (a: number) => queueMicrotask(self.getObject(a));
    i.wbg.__wbg_queueMicrotask_d3219def82552485 = (a: number) => self.addHeapObject(self.getObject(a).queueMicrotask);
    
    // Wbindgen internals
    i.wbg.__wbindgen_cb_drop = (a: number) => { const o = self.takeObject(a).original; if (o.cnt-- == 1) { o.a = 0; return true; } return false; };
    i.wbg.__wbindgen_closure_wrapper982 = (a: number, b: number) => { 
      const s: any = { a, b, cnt: 1, dtor: 36 }; 
      const r: any = (...args: any[]) => { 
        s.cnt++; const t = s.a; s.a = 0; 
        try { return self.wasm.__wbindgen_export_5(t, s.b, self.addHeapObject(args[0])); } 
        finally { if (--s.cnt === 0) self.wasm.__wbindgen_export_3.get(s.dtor)(t, s.b); else s.a = t; } 
      }; 
      r.original = s; 
      return self.addHeapObject(r); 
    };
    i.wbg.__wbindgen_is_function = (a: number) => typeof self.getObject(a) === 'function';
    i.wbg.__wbindgen_is_undefined = (a: number) => self.getObject(a) === undefined;
    i.wbg.__wbindgen_object_clone_ref = (a: number) => self.addHeapObject(self.getObject(a));
    i.wbg.__wbindgen_object_drop_ref = (a: number) => self.takeObject(a);
    i.wbg.__wbindgen_string_new = (a: number, b: number) => self.addHeapObject(self.getStringFromWasm0(a, b));
    i.wbg.__wbindgen_throw = (a: number, b: number) => { throw new Error(self.getStringFromWasm0(a, b)); };
    
    return i;
  }

  async initialize(wasmModule: WebAssembly.Module): Promise<this> {
    const imports = this.buildImports();
    // Use WebAssembly.Module directly (bundled by wrangler at build time)
    // This avoids the "Wasm code generation disallowed" error
    const instance = await WebAssembly.instantiate(wasmModule, imports);
    this.wasm = instance.exports;
    return this;
  }

  getImgKey(): string {
    const retptr = this.wasm.__wbindgen_add_to_stack_pointer(-16);
    try {
      this.wasm.get_img_key(retptr);
      const dv = this.getDataViewMemory0();
      const r0 = dv.getInt32(retptr, true);
      const r1 = dv.getInt32(retptr + 4, true);
      const r2 = dv.getInt32(retptr + 8, true);
      const r3 = dv.getInt32(retptr + 12, true);
      if (r3) throw this.takeObject(r2);
      const result = this.getStringFromWasm0(r0, r1);
      this.wasm.__wbindgen_export_4(r0, r1, 1);
      return result;
    } finally {
      this.wasm.__wbindgen_add_to_stack_pointer(16);
    }
  }

  async processImgData(data: string, key: string): Promise<any> {
    const p0 = this.passStringToWasm0(data, this.wasm.__wbindgen_export_1);
    const l0 = this.WASM_VECTOR_LEN;
    const p1 = this.passStringToWasm0(key, this.wasm.__wbindgen_export_1);
    const l1 = this.WASM_VECTOR_LEN;
    return this.takeObject(this.wasm.process_img_data(p0, l0, p1, l1));
  }
}

// Cached WASM instance (reused across requests)
let cachedWasmLoader: FlixerWasmLoader | null = null;
let cachedApiKey: string | null = null;
let serverTimeOffset = 0;

/**
 * Sync with Flixer server time
 */
async function syncServerTime(): Promise<void> {
  const localTimeBefore = Date.now();
  const response = await fetch(`${FLIXER_API_BASE}/api/time?t=${localTimeBefore}`);
  const localTimeAfter = Date.now();
  const data = await response.json() as { timestamp: number };
  
  const rtt = localTimeAfter - localTimeBefore;
  const serverTimeMs = data.timestamp * 1000;
  serverTimeOffset = serverTimeMs + (rtt / 2) - localTimeAfter;
}

function getServerTimestamp(): number {
  return Math.floor((Date.now() + serverTimeOffset) / 1000);
}

/**
 * Generate client fingerprint matching the browser implementation
 */
function generateClientFingerprint(): string {
  const screenWidth = 2560;
  const screenHeight = 1440;
  const colorDepth = 24;
  const platform = 'Win32';
  const language = 'en-US';
  const timezoneOffset = new Date().getTimezoneOffset();
  const userAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36';
  const canvasSubstr = 'iVBORw0KGgoAAAANSUhEUgAAASwA';
  
  const fpString = `${screenWidth}x${screenHeight}:${colorDepth}:${userAgent.substring(0, 50)}:${platform}:${language}:${timezoneOffset}:${canvasSubstr}`;
  
  let hash = 0;
  for (let i = 0; i < fpString.length; i++) {
    hash = (hash << 5) - hash + fpString.charCodeAt(i);
    hash &= hash;
  }
  
  return Math.abs(hash).toString(36);
}

/**
 * Generate authentication headers for Flixer API
 */
function generateAuthHeaders(apiKey: string, path: string): Record<string, string> {
  const timestamp = getServerTimestamp();
  
  // Generate nonce - 22 chars from base64
  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const nonce = btoa(String.fromCharCode(...nonceBytes))
    .replace(/[/+=]/g, '').substring(0, 22);
  
  // Generate HMAC-SHA256 signature
  const message = `${apiKey}:${timestamp}:${nonce}:${path}`;
  
  // Use SubtleCrypto for HMAC (async, but we'll handle it)
  // For now, use a simple hash since we need sync
  // The actual signature is computed in the request function
  
  return {
    'X-Api-Key': apiKey,
    'X-Request-Timestamp': timestamp.toString(),
    'X-Request-Nonce': nonce,
    'X-Client-Fingerprint': generateClientFingerprint(),
    'Accept': 'text/plain',
    'Accept-Language': 'en-US,en;q=0.9',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
    'Referer': 'https://flixer.sh/',
    'sec-ch-ua': '"Chromium";v="143", "Not A(Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
  };
}

/**
 * Make authenticated API request to Flixer
 */
async function makeFlixerRequest(
  apiKey: string,
  path: string,
  extraHeaders: Record<string, string> = {}
): Promise<string> {
  const timestamp = getServerTimestamp();
  const nonceBytes = new Uint8Array(16);
  crypto.getRandomValues(nonceBytes);
  const nonce = btoa(String.fromCharCode(...nonceBytes))
    .replace(/[/+=]/g, '').substring(0, 22);
  
  // Generate HMAC-SHA256 signature
  const message = `${apiKey}:${timestamp}:${nonce}:${path}`;
  const encoder = new TextEncoder();
  const keyData = encoder.encode(apiKey);
  const messageData = encoder.encode(message);
  
  const cryptoKey = await crypto.subtle.importKey(
    'raw', keyData, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, messageData);
  const signature = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));
  
  const headers: Record<string, string> = {
    'X-Api-Key': apiKey,
    'X-Request-Timestamp': timestamp.toString(),
    'X-Request-Nonce': nonce,
    'X-Request-Signature': signature,
    'X-Client-Fingerprint': generateClientFingerprint(),
    'Accept': 'text/plain',
    'Accept-Language': 'en-US,en;q=0.9',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/143.0.0.0 Safari/537.36',
    'Referer': 'https://flixer.sh/',
    'sec-ch-ua': '"Chromium";v="143", "Not A(Brand";v="24"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    ...extraHeaders,
  };
  
  // CRITICAL: Do NOT send these headers - they cause the request to be blocked
  // - bW90aGFmYWth (base64 for "mothafaka") - anti-scraping marker
  // - Origin header
  // - sec-fetch-* headers
  
  const response = await fetch(`${FLIXER_API_BASE}${path}`, {
    headers,
    signal: AbortSignal.timeout(15000),
  });
  
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}: ${await response.text()}`);
  }
  
  return response.text();
}

/**
 * Get source URL from a specific server with retries
 */
async function getSourceFromServer(
  loader: FlixerWasmLoader,
  apiKey: string,
  type: string,
  tmdbId: string,
  server: string,
  seasonId?: string,
  episodeId?: string,
  retries = 5
): Promise<{ url: string | null; raw: any }> {
  const path = type === 'movie'
    ? `/api/tmdb/movie/${tmdbId}/images`
    : `/api/tmdb/tv/${tmdbId}/season/${seasonId}/episode/${episodeId}/images`;

  // Make a "warm-up" request without X-Server header
  try {
    await makeFlixerRequest(apiKey, path, {});
  } catch (e) {
    // Expected to fail sometimes
  }
  
  await new Promise(r => setTimeout(r, 100));

  for (let attempt = 1; attempt <= retries; attempt++) {
    const encrypted = await makeFlixerRequest(apiKey, path, {
      'X-Only-Sources': '1',
      'X-Server': server,
    });

    const decrypted = await loader.processImgData(encrypted, apiKey);
    const data = JSON.parse(decrypted);

    // Extract URL from various possible locations
    let url: string | null = null;
    
    if (Array.isArray(data.sources)) {
      const source = data.sources.find((s: any) => s.server === server) || data.sources[0];
      url = source?.url || source?.file || source?.stream;
      if (!url && source?.sources) {
        url = source.sources[0]?.url || source.sources[0]?.file;
      }
    }
    
    if (!url) {
      url = data.sources?.file || data.sources?.url || data.file || data.url || data.stream;
    }
    
    if (!url && data.servers && data.servers[server]) {
      const serverData = data.servers[server];
      url = serverData.url || serverData.file || serverData.stream;
      if (Array.isArray(serverData)) {
        url = serverData[0]?.url || serverData[0]?.file;
      }
    }

    if (url && url.trim() !== '') {
      return { url, raw: data };
    }
    
    if (attempt < retries) {
      await new Promise(r => setTimeout(r, 200));
    }
  }

  return { url: null, raw: null };
}

/**
 * Main handler for Flixer proxy requests
 */
export async function handleFlixerRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const path = url.pathname;
  const logLevel = (env.LOG_LEVEL || 'info') as LogLevel;
  const logger = createLogger(request, logLevel);

  // CORS preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { status: 204, headers: corsHeaders() });
  }

  // Health check
  if (path === '/flixer/health' || path.endsWith('/health')) {
    return jsonResponse({
      status: 'ok',
      wasmLoaded: !!cachedWasmLoader,
      hasApiKey: !!cachedApiKey,
      serverTimeOffset,
      timestamp: new Date().toISOString(),
    }, 200);
  }

  // Extract endpoint
  if (path === '/flixer/extract' || path === '/flixer') {
    const tmdbId = url.searchParams.get('tmdbId');
    const type = url.searchParams.get('type') || 'movie';
    const season = url.searchParams.get('season');
    const episode = url.searchParams.get('episode');
    const server = url.searchParams.get('server') || 'alpha';

    if (!tmdbId) {
      return jsonResponse({ error: 'Missing tmdbId parameter' }, 400);
    }

    if (type === 'tv' && (!season || !episode)) {
      return jsonResponse({ error: 'Season and episode required for TV shows' }, 400);
    }

    try {
      // Initialize WASM if not cached
      if (!cachedWasmLoader || !cachedApiKey) {
        logger.info('Initializing Flixer WASM...');
        
        // Use bundled WASM module (imported at top of file)
        // This avoids the "Wasm code generation disallowed by embedder" error
        // that occurs when trying to fetch and instantiate WASM at runtime
        
        // Sync server time
        await syncServerTime();
        
        // Initialize loader with bundled WASM
        cachedWasmLoader = new FlixerWasmLoader();
        await cachedWasmLoader.initialize(FLIXER_WASM);
        cachedApiKey = cachedWasmLoader.getImgKey();
        
        logger.info('Flixer WASM initialized', { keyPrefix: cachedApiKey.slice(0, 16) });
      }

      // Get source from server
      const result = await getSourceFromServer(
        cachedWasmLoader,
        cachedApiKey,
        type,
        tmdbId,
        server,
        season || undefined,
        episode || undefined
      );

      if (!result.url) {
        return jsonResponse({
          success: false,
          error: 'No stream URL found',
          server,
        }, 404);
      }

      const displayName = SERVER_NAMES[server] || server;
      
      return jsonResponse({
        success: true,
        sources: [{
          quality: 'auto',
          title: `Flixer ${displayName}`,
          url: result.url,
          type: 'hls',
          referer: 'https://flixer.sh/',
          requiresSegmentProxy: true,
          status: 'working',
          language: 'en',
          server,
        }],
        server,
        timestamp: new Date().toISOString(),
      }, 200);

    } catch (error) {
      logger.error('Flixer extraction error', error as Error);
      
      // Reset cache on error
      cachedWasmLoader = null;
      cachedApiKey = null;
      
      return jsonResponse({
        success: false,
        error: error instanceof Error ? error.message : String(error),
      }, 500);
    }
  }

  return jsonResponse({ error: 'Unknown endpoint' }, 404);
}

export default {
  fetch: handleFlixerRequest,
};
