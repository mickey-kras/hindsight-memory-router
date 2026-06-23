declare type Buffer = any;
declare const Buffer: any;
declare const process: any;

declare module "node:fs" {
  export const readFileSync: any;
  export const appendFileSync: any;
  export const mkdirSync: any;
}

declare module "node:path" {
  export const dirname: any;
}

declare module "node:crypto" {
  export const createHash: any;
}

declare module "node:http" {
  export const createServer: any;
  export type IncomingMessage = any;
  export type ServerResponse = any;
}

declare module "node:url" {
  export const URL: any;
}
