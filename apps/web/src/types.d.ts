declare namespace JSX {
  interface IntrinsicElements {
    [elemName: string]: Record<string, unknown>;
  }
}

declare module '*.css' {}

declare module 'react' {
  export type ReactNode = unknown;
  export function useState<T>(initial: T | (() => T)): [T, (next: T | ((prev: T) => T)) => void];
  export function useEffect(effect: () => void | (() => void), deps?: readonly unknown[]): void;
  const React: {
    useState: typeof useState;
    useEffect: typeof useEffect;
  };
  export default React;
}
