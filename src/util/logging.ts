/** biome-ignore-all lint/suspicious/noExplicitAny: proxied requests could literaly be anything */
/** biome-ignore-all lint/correctness/noUnusedVariables: used for "pick" operations */
import type http from "node:http";
import type { ProxiedHeaders, ProxiedRequest } from "../types/types";

export function sanitizeHeadersForLogging(headers: ProxiedHeaders) {
  const { agent, ...otherHeaders } = headers ?? {};
  const { _sessionCache, ...rest } = agent ?? {};
  const sanitizedHeaders = {
    ...otherHeaders,
    agent: { ...rest },
  } as unknown as http.IncomingHttpHeaders;
  return sanitizedHeaders;
}

export function sanitizeRequestForLogging(req: ProxiedRequest) {
  const reqClone = { ...req };
  const sanitizedHeaders = sanitizeHeadersForLogging(req.headers ?? {});
  reqClone.headers = sanitizedHeaders;
  const { parser, ...reqWithoutParser } = reqClone as any;
  const { sockets: z1, agent, res, ...otherHeaders } = reqWithoutParser ?? {};
  const { _sessionCache, sockets: z2, ...rest } = agent ?? {}; // sanitize "agent"
  const { socket, client, req: req2, ...otherResponseProps } = res ?? {};
  const sanitizedReq = {
    ...otherHeaders,
    agent: { ...rest },
    res: { ...otherResponseProps },
  };
  return sanitizedReq;
}
