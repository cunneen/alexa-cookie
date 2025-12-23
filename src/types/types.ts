import type * as http from "node:http";
import type { OutgoingHttpHeaders } from "node:http";
import type { RequestOptions as HTTPRequestOptions } from "node:https";
import type * as net from "node:net";
import type express from "express";
import type * as httpProxy from "http-proxy";

export type CookieMap = {
  [key: string]: string | string[] | undefined | number;
  amazonPage?: string | undefined;
  loginCookie?: string | undefined;
  authorization_code?: string | string[] | undefined;
  frc?: string | undefined;
  "map-md"?: string | undefined;
  deviceId?: string | undefined;
  verifier?: string | undefined;
  tokenDate?: number | undefined;
  localCookie?: string | undefined;
  refreshToken?: string | undefined;
};

export type Router =
  | {
      [hostOrPath: string]: httpProxy.ServerOptions["target"];
    }
  | ((req: express.Request) => httpProxy.ServerOptions["target"])
  | ((req: Request) => Promise<httpProxy.ServerOptions["target"]>);

export type LoggerFunction = (...args: unknown[]) => void;
export type Logger = {
  log: LoggerFunction;
  debug: LoggerFunction;
  info: LoggerFunction;
  warn: LoggerFunction;
  error: LoggerFunction;
  trace?: LoggerFunction;
  flush?: (err?: Error) => void;
};

export type RegistrationData = {
  // [x: string]: string
  frc?: string;
  deviceId?: string;
  loginCookie?: string;
  accessToken?: string;
  refreshToken?: string;
  tokenDate?: number;
  amazonPage?: string;
  deviceSerial?: string;
  "map-md"?: string;
};

export type AmazonProxyOptions = {
  /** optional: webpage language, should match to amazon-Page, default is 'de-DE' */
  acceptLanguage?: string;
  /** optional: possible to use with different countries, default is 'amazon.de' */
  amazonPage?: string;
  /** optional: language to be used for the Amazon Sign-in page the proxy calls. default is "de_DE") */
  amazonPageProxyLanguage?: string;
  /** optional: Change the Proxy Amazon Page - all "western countries" directly use amazon.com including australia! Change to amazon.co.jp for Japan */
  baseAmazonPage?: string;
  /** do not use. This is used internally; it's either set automatically to "_jp" or "" */
  baseAmazonPageHandle?: string;
  /** optional: name of the device app name which will be registered with Amazon, leave empty to use a default one */
  deviceAppName?: string;
  /** optional: overwrite path where some of the formerRegistrationData are persisted to optimize against Amazon security measures */
  formerDataStorePath?: string;
  /** optional/preferred: provide the result object from subsequent proxy usages here and some generated data will be reused for next proxy call too */
  formerRegistrationData?: RegistrationData;
  /** a logger that provides log, debug, info, warn and error methods (easiest to use the console object) */
  logger?: Logger;
  /** optional: use in order to override the default html displayed when the proxy window can be closed, default is '<b>Amazon Alexa Cookie successfully retrieved. You can close the browser.</b>' */
  proxyCloseWindowHTML?: string;
  /** optional: set this to bind the proxy to a special IP, default is '0.0.0.0' */
  proxyListenBind?: string;
  /**  optional: Loglevel of Proxy, default 'warn' */
  proxyLogLevel?: string;
  /** optional: should only the proxy method be used? When no email/password are provided this will set to true automatically, default: false */
  proxyOnly?: boolean;
  /** optional: should the library setup a proxy to get cookie when automatic way did not worked? Default false! */
  setupProxy?: boolean;

  /**
   * required if proxy enabled: provide the own IP with which you later access the proxy.
   * Providing/Using a hostname here can lead to issues!
   * Needed to set up all rewriting and proxy stuff internally.
   */
  proxyOwnIp?: string;
  /** optional: use this port for the proxy, default is 0 means random port is selected */
  proxyPort?: number | undefined;
  /** optional: own userAgent to use for all request, overwrites default one, should not be needed */
  userAgent?: string;
};

export type RequestInfoType = {
  requests: { options: HTTPRequestOptions; response: http.IncomingMessage }[];
};

export type ErrorParam = Error | 0 | unknown;

// biome-ignore lint/suspicious/noExplicitAny: due to argument shifting, needs to be flexible
export type RequestCallbackType = (error?: ErrorParam, ...args: any[]) => void;

export type ProxyServer = http.Server<
  typeof http.IncomingMessage,
  typeof http.ServerResponse
> | null;

export type ProxiedHeaders = {
  agent?: { _sessionCache?: object & string & string[] & undefined };
} & (
  | http.IncomingHttpHeaders
  | (
      | http.OutgoingHttpHeaders
      | { getHeader: (header: string) => string | undefined | number }
    )
);

export type ProxiedRequest = {
  headers?: ProxiedHeaders;
} & http.ClientRequest;

export type ListeningCallbackType = ((server: ProxyServer) => void) | null;

export interface ProxyResponseSocketType extends net.Socket {
  _host?: string;
  parser: {
    outgoing: {
      method?: string;
      path?: string;
      getHeader: (header: string) => string | number | undefined;
    };
  };
}
export type RequestOptions = HTTPRequestOptions & {
  headers: /* {[key: CapitalizedHeaderNames]: string} &  */ OutgoingHttpHeaders;
  body?: string | Record<string, string>;
  followRedirects?: boolean;
  gzip?: boolean;
};
