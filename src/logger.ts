/**
 * Logger utility for Cloudflare Workers
 * Provides structured logging with request context
 */

export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogContext {
  requestId: string;
  method?: string;
  path?: string;
  url?: string;
  [key: string]: any;
}

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  context?: LogContext;
  data?: any;
  duration?: number;
  error?: {
    name: string;
    message: string;
    stack?: string;
  };
}

const LOG_LEVELS: Record<LogLevel, number> = {
  debug: 0,
  info: 1,
  warn: 2,
  error: 3,
};

export class Logger {
  private context: LogContext;
  private startTime: number;
  private minLevel: LogLevel;

  constructor(requestId: string, minLevel: LogLevel = 'debug') {
    this.context = { requestId };
    this.startTime = Date.now();
    this.minLevel = minLevel;
  }

  setContext(ctx: Partial<LogContext>) {
    this.context = { ...this.context, ...ctx };
  }

  private shouldLog(level: LogLevel): boolean {
    return LOG_LEVELS[level] >= LOG_LEVELS[this.minLevel];
  }

  private formatEntry(level: LogLevel, message: string, data?: any, error?: Error): LogEntry {
    const entry: LogEntry = {
      timestamp: new Date().toISOString(),
      level,
      message,
      context: this.context,
      duration: Date.now() - this.startTime,
    };

    if (data !== undefined) {
      entry.data = data;
    }

    if (error) {
      entry.error = {
        name: error.name,
        message: error.message,
        stack: error.stack,
      };
    }

    return entry;
  }

  private log(level: LogLevel, message: string, data?: any, error?: Error) {
    if (!this.shouldLog(level)) return;

    const entry = this.formatEntry(level, message, data, error);
    const logFn = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
    
    // Output as JSON for structured logging in Cloudflare dashboard
    logFn(JSON.stringify(entry));
  }

  debug(message: string, data?: any) {
    this.log('debug', message, data);
  }

  info(message: string, data?: any) {
    this.log('info', message, data);
  }

  warn(message: string, data?: any) {
    this.log('warn', message, data);
  }

  error(message: string, error?: Error | any, data?: any) {
    if (error instanceof Error) {
      this.log('error', message, data, error);
    } else {
      this.log('error', message, { ...data, errorDetails: error });
    }
  }

  // Log request start
  requestStart(request: Request) {
    const url = new URL(request.url);
    this.setContext({
      method: request.method,
      path: url.pathname,
      url: url.toString(),
    });
    this.info('Request started', {
      headers: Object.fromEntries(request.headers),
      query: Object.fromEntries(url.searchParams),
    });
  }

  // Log request end with response details
  requestEnd(response: Response, cached: boolean = false) {
    this.info('Request completed', {
      status: response.status,
      statusText: response.statusText,
      cached,
      contentType: response.headers.get('content-type'),
      contentLength: response.headers.get('content-length'),
    });
  }

  // Log upstream fetch
  fetchStart(url: string, options?: any) {
    this.debug('Fetching upstream', { url: url.substring(0, 200), options });
  }

  fetchEnd(url: string, status: number, duration: number) {
    this.debug('Upstream response', { 
      url: url.substring(0, 200), 
      status, 
      fetchDuration: duration 
    });
  }

  fetchError(url: string, error: Error) {
    this.error('Upstream fetch failed', error, { url: url.substring(0, 200) });
  }
}

// Generate a unique request ID
export function generateRequestId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).substring(2, 9)}`;
}

// Create logger from request
export function createLogger(request: Request, logLevel: LogLevel = 'debug'): Logger {
  const requestId = request.headers.get('x-request-id') || generateRequestId();
  const logger = new Logger(requestId, logLevel);
  logger.requestStart(request);
  return logger;
}
