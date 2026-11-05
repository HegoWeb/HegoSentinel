declare namespace NodeJS {
  type Signals = string;

  interface ErrnoException extends Error {
    errno?: number;
    code?: string;
    path?: string;
    syscall?: string;
  }

  interface ProcessEnv {
    [key: string]: string | undefined;
  }

  interface WriteStream {
    write(chunk: string): boolean;
    end(chunk?: string): void;
  }

  interface ReadStream {
    on(event: 'data', listener: (chunk: Buffer | string) => void): this;
    on(event: string, listener: (...args: any[]) => void): this;
  }
}

interface Process {
  argv: string[];
  execPath: string;
  env: NodeJS.ProcessEnv;
  platform: string;
  version: string;
  cwd(): string;
  getuid?(): number;
  getgid?(): number;
  kill(pid: number, signal?: string | number): boolean;
  exitCode?: number;
  exit(code?: number): never;
  stdout: NodeJS.WriteStream;
  stderr: NodeJS.WriteStream;
  on(event: string, listener: (...args: unknown[]) => void): this;
}

declare var process: Process;

declare module 'node:os' {
  export function tmpdir(): string;
  export function release(): string;
}

declare module 'node:crypto' {
  export interface Hash {
    update(data: string, inputEncoding?: 'utf8' | 'ascii' | 'hex'): Hash;
    digest(encoding: 'hex' | 'base64' | 'base64url'): string;
  }
  export interface Hmac {
    update(data: string, inputEncoding?: 'utf8' | 'ascii' | 'hex'): Hmac;
    digest(encoding: 'hex' | 'base64' | 'base64url'): string;
  }
  export function createHash(algorithm: string): Hash;
  export function createHmac(algorithm: string, key: string): Hmac;
  export function randomUUID(): string;
}

declare module 'node:net' {
  export function isIP(input: string): 0 | 4 | 6;
}

declare module 'node:fs' {
  export interface Stats {
    isDirectory(): boolean;
    isFile(): boolean;
    isSymbolicLink(): boolean;
    size: number;
  }
  export function existsSync(path: string): boolean;
  export function statSync(path: string): Stats;
  export function lstatSync(path: string): Stats;
  export function realpathSync(path: string): string;
  export function symlinkSync(
    target: string,
    path: string,
    type?: 'dir' | 'file' | 'junction'
  ): void;
  export function rmSync(
    path: string,
    options?: { recursive?: boolean; force?: boolean }
  ): void;
  export function mkdirSync(path: string, options?: { recursive?: boolean }): string | undefined;
  export function readFileSync(path: string, encoding: 'utf8' | 'utf-8'): string;
  export function writeFileSync(
    path: string,
    data: string,
    encoding?: 'utf8' | 'utf-8'
  ): void;
  export function readdirSync(path: string): string[];
}

declare module 'node:path' {
  export function resolve(...paths: string[]): string;
  export function relative(from: string, to: string): string;
  export function isAbsolute(path: string): boolean;
  export function dirname(path: string): string;
  export function join(...paths: string[]): string;
  export function extname(path: string): string;
}

declare module 'node:url' {
  export function fileURLToPath(url: string | URL): string;
  export function pathToFileURL(path: string): URL;
}

declare module 'node:module' {
  export interface StripTypeScriptTypesOptions {
    mode?: 'strip' | 'transform';
    sourceUrl?: string;
  }
  export function stripTypeScriptTypes(
    code: string,
    options?: StripTypeScriptTypesOptions
  ): string;
}

declare module 'node:child_process' {
  export interface ExecFileOptions {
    shell?: boolean;
    timeout?: number;
    maxBuffer?: number;
    windowsHide?: boolean;
    cwd?: string;
    env?: NodeJS.ProcessEnv;
    killSignal?: string;
    stdio?: string | readonly string[];
  }
  export interface ChildProcess {
    pid?: number;
    exitCode?: number | null;
    killed: boolean;
    stdin: NodeJS.WriteStream;
    stdout: NodeJS.ReadStream;
    stderr: NodeJS.ReadStream;
    kill(signal?: string | number): boolean;
    on(event: string, listener: (...args: any[]) => void): this;
    once(event: string, listener: (...args: any[]) => void): this;
  }
  export function execFile(
    file: string,
    args: readonly string[],
    options: ExecFileOptions,
    callback: (error: NodeJS.ErrnoException | null, stdout: string, stderr: string) => void
  ): ChildProcess;
  export function spawn(
    command: string,
    args?: readonly string[],
    options?: ExecFileOptions
  ): ChildProcess;
  export function spawnSync(
    command: string,
    args?: readonly string[],
    options?: ExecFileOptions
  ): { status: number | null; stdout: Buffer | string; stderr: Buffer | string };
}

declare module 'node:http' {
  export interface IncomingMessage {
    method?: string;
    url?: string;
    headers: Record<string, string | string[] | undefined>;
    destroy?(): void;
    on(event: 'data', listener: (chunk: unknown) => void): this;
    on(event: 'end', listener: () => void): this;
    on(event: string, listener: (...args: unknown[]) => void): this;
  }

  export interface ServerResponse {
    statusCode: number;
    setHeader(name: string, value: string | string[]): void;
    writeHead(statusCode: number, headers?: Record<string, string>): this;
    end(data?: string): this;
  }

  export interface Server {
    listen(port: number, hostname?: string, listeningListener?: () => void): this;
    address?(): { port: number; address: string } | string | null;
    close(callback?: (err?: Error) => void): this;
    on(event: string, listener: (...args: unknown[]) => void): this;
    headersTimeout?: number;
    requestTimeout?: number;
  }

  export function createServer(
    requestListener: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>
  ): Server;
}

declare module 'node:assert/strict' {
  export function equal<T>(actual: T, expected: T, message?: string): void;
  export function notEqual<T>(actual: unknown, expected: unknown, message?: string): void;
  export function strictEqual<T>(actual: T, expected: T, message?: string): void;
  export function deepEqual<T>(actual: T, expected: T, message?: string): void;
  export function ok(value: unknown, message?: string): asserts value;
  export function match(string: string, regexp: RegExp, message?: string): void;
  const assert: {
    equal: typeof equal;
    notEqual: typeof notEqual;
    strictEqual: typeof strictEqual;
    deepEqual: typeof deepEqual;
    ok: typeof ok;
    match: typeof match;
  };
  export default assert;
}

declare module 'node:test' {
  export interface TestContext {
    skip(message?: string): void;
  }
  export type TestFn = (t: TestContext) => void | Promise<void>;
  export function describe(name: string, fn: () => void): void;
  export function it(name: string, fn: TestFn): void;
  export function test(name: string, fn: TestFn): void;
  export function before(fn: TestFn): void;
  export function after(fn: TestFn): void;
}


declare module 'node:events' {
  export class EventEmitter {
    on(event: string, listener: (...args: unknown[]) => void): this;
    emit(event: string, ...args: unknown[]): boolean;
  }
}
