/* jshint -W097 */
/* jshint -W030 */
/* jshint strict: false */
/* jslint node: true */
/* jslint esversion: 6 */

import {
  randomBytes,
  randomFillSync,
} from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import type * as http from "node:http";
import { dirname, join as pathJoin } from "node:path";
import { parse as cookieToolsParse } from "cookie";
import express from "express";
import { createProxyMiddleware as proxy } from "http-proxy-middleware";
import type {
  LogProviderCallback,
  OnErrorCallback,
  OnProxyReqCallback,
  OnProxyResCallback,
  Options,
} from "http-proxy-middleware/dist/types";
import modifyResponse from "node-http-proxy-json";
import { parse as queryStringParse } from "querystring";
import type {
  AmazonProxyOptions,
  CookieMap,
  ErrorParam,
  ListeningCallbackType,
  Logger,
  ProxyResponseSocketType,
  Router,
} from "../types/types";
import { base64URLEncode } from "../util/base64URLEncode";
import { customStringify } from "../util/customStringify";
import { LoggingFacade } from "../util/LoggingFacade";
import {
  sanitizeRequestForLogging,
} from "../util/logging";
import { sha256 } from "../util/sha256";

const FORMERDATA_STORE_VERSION = 4;

function addCookies(Cookie: string, headers: http.IncomingHttpHeaders): string {
  if (!headers || !headers["set-cookie"]) return Cookie;
  const cookies = cookieToolsParse(Cookie);
  for (const thisCookie of headers["set-cookie"]) {
    const cookie = thisCookie.match(/^([^=]+)=([^;]+);.*/);
    if (cookie && cookie.length === 3 && cookie[1] && cookie[2]) {
      if (cookie[1] === "ap-fid" && cookie[2] === '""') continue;
      cookies[cookie[1]] = cookie[2];
    }
  }
  Cookie = "";
  for (const name of Object.keys(cookies)) {
    Cookie += `${name}=${cookies[name]}; `;
  }
  Cookie = Cookie.replace(/[; ]*$/, "");
  return Cookie;
}

function initAmazonProxy(
  _options: AmazonProxyOptions,
  callbackCookieFn: (err: ErrorParam, cookieInfo: CookieMap) => void,
  callbackListening: ListeningCallbackType,
) {
  if (!_options.logger) {
    _options.logger = new LoggingFacade(); // "no-op" logger
  }

  const logger = _options.logger;

  const initialCookies = {} as CookieMap;

  const formerDataStorePath =
    _options.formerDataStorePath ||
    pathJoin(__dirname, "../../data", "formerDataStore.json");
  let formerDataStoreValid = false;
  if (!_options.formerRegistrationData) {
    try {
      if (existsSync(formerDataStorePath)) {
        const formerDataStore = JSON.parse(
          readFileSync(formerDataStorePath, "utf8"),
        );
        if (
          typeof formerDataStore === "object" &&
          formerDataStore.storeVersion === FORMERDATA_STORE_VERSION
        ) {
          _options.formerRegistrationData =
            _options.formerRegistrationData || {};
          _options.formerRegistrationData.frc =
            _options.formerRegistrationData.frc || formerDataStore.frc;
          _options.formerRegistrationData["map-md"] =
            _options.formerRegistrationData["map-md"] ||
            formerDataStore["map-md"];
          _options.formerRegistrationData.deviceId =
            _options.formerRegistrationData.deviceId ||
            formerDataStore.deviceId;
          logger.info(
            "Proxy Init: loaded temp data store as fallback registration data",
          );
          formerDataStoreValid = true;
        }
      } else {
        if (!existsSync(dirname(formerDataStorePath))) {
          // ensure directories
          mkdirSync(dirname(formerDataStorePath));
        }
      }
    } catch (_err) {
      // ignore
    }
  }

  if (!_options.baseAmazonPage) {
    _options.baseAmazonPage = "amazon.com";
  }

  if (
    !_options.formerRegistrationData ||
    !_options.formerRegistrationData.frc
  ) {
    // frc contains 313 random bytes, encoded as base64
    const frcBuffer = Buffer.alloc(313);
    for (let i = 0; i < 313; i++) {
      frcBuffer.writeUInt8(Math.floor(Math.random() * 255), i);
    }
    initialCookies.frc = frcBuffer.toString("base64");
  } else {
    logger.info("Proxy Init: reuse frc from former data");
    initialCookies.frc = _options.formerRegistrationData.frc;
  }

  if (
    !_options.formerRegistrationData ||
    !_options.formerRegistrationData["map-md"]
  ) {
    // map-md contains (hard-coded) device information, encoded as base64
    initialCookies["map-md"] = Buffer.from(
      '{"device_user_dictionary":[],"device_registration_data":{"software_version":"1"},"app_identifier":{"app_version":"2.2.485407","bundle_id":"com.amazon.echo"}}',
    ).toString("base64");
  } else {
    logger.info("Proxy Init: reuse map-md from former data");
    initialCookies["map-md"] = _options.formerRegistrationData["map-md"];
  }

  let deviceId = "";
  if (
    !_options.formerRegistrationData ||
    !_options.formerRegistrationData.deviceId ||
    !formerDataStoreValid
  ) {
    // deviceID is a random 32-character hex string concatenated with a hard-coded deviceID hex string
    const buf = Buffer.alloc(16); // 16 random bytes
    const bufHex = randomFillSync(buf).toString("hex").toUpperCase(); // convert into hex = 32x 0-9A-F
    deviceId = Buffer.from(bufHex).toString("hex"); // convert into hex = 64 chars that are hex of hex id
    deviceId += "23413249564c5635564d32573831";
  } else {
    logger.info("Proxy Init: reuse deviceId from former data");
    deviceId = _options.formerRegistrationData.deviceId;
  }

  try {
    const formerDataStore = {
      storeVersion: FORMERDATA_STORE_VERSION,
      deviceId: deviceId,
      "map-md": initialCookies["map-md"],
      frc: initialCookies.frc,
    };
    writeFileSync(formerDataStorePath, JSON.stringify(formerDataStore), "utf8");
    logger.debug(`saved registration data at: ${formerDataStorePath}`)
  } catch (_err) {
    logger.warn(`could not save registration data at: ${formerDataStorePath}`)
  }

  const code_verifier = base64URLEncode(randomBytes(32));
  const code_challenge = base64URLEncode(sha256(code_verifier));

  let proxyCookies = "";

  // proxy middleware options

  let returnedInitUrl: string = "";

  const router: Router = (req: express.Request) => {
    const url = req.originalUrl || req.url;
    _options.logger = _options.logger as Logger;
    logger.info(
      `Router: ${url} / ${req.method} / ${customStringify(req.headers,null,2)}`
    );
    if (req.headers.host === `${_options.proxyOwnIp}:${_options.proxyPort}`) {
      if (url.startsWith(`/www.${_options.baseAmazonPage}/`)) {
        return `https://www.${_options.baseAmazonPage}`;
      } else if (url.startsWith(`/alexa.${_options.baseAmazonPage}/`)) {
        return `https://alexa.${_options.baseAmazonPage}`;
      } else if (req.headers.referer) {
        if (
          req.headers.referer.startsWith(
            `http://${_options.proxyOwnIp}:${_options.proxyPort}/www.${_options.baseAmazonPage}/`,
          )
        ) {
          return `https://www.${_options.baseAmazonPage}`;
        } else if (
          req.headers.referer.startsWith(
            `http://${_options.proxyOwnIp}:${_options.proxyPort}/alexa.${_options.baseAmazonPage}/`,
          )
        ) {
          return `https://alexa.${_options.baseAmazonPage}`;
        }
      }
      if (url === "/") {
        // initial redirect
        returnedInitUrl = `https://www.${_options.baseAmazonPage}/ap/signin?openid.return_to=https%3A%2F%2Fwww.${_options.baseAmazonPage}%2Fap%2Fmaplanding&openid.assoc_handle=amzn_dp_project_dee_ios${_options.baseAmazonPageHandle}&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&pageId=amzn_dp_project_dee_ios${_options.baseAmazonPageHandle}&accountStatusPolicy=P1&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select&openid.mode=checkid_setup&openid.ns.oa2=http%3A%2F%2Fwww.${_options.baseAmazonPage}%2Fap%2Fext%2Foauth%2F2&openid.oa2.client_id=device%3A${deviceId}&openid.ns.pape=http%3A%2F%2Fspecs.openid.net%2Fextensions%2Fpape%2F1.0&openid.oa2.response_type=code&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0&openid.pape.max_auth_age=0&openid.oa2.scope=device_auth_access&openid.oa2.code_challenge_method=S256&openid.oa2.code_challenge=${code_challenge}&language=${_options.amazonPageProxyLanguage}`;
        logger.info(`Alexa-Cookie: Initial Page Request: ${returnedInitUrl}`);
        return returnedInitUrl;
      } else {
        return `https://www.${_options.baseAmazonPage}`;
      }
    }
    return `https://alexa.${_options.baseAmazonPage}`;
  };

  const onError: OnErrorCallback = (err, _req, res) => {
    _options.logger = _options.logger as Logger;

    logger.error(err);
    try {
      res.writeHead(500, {
        "Content-Type": "text/plain",
      });
      res.end(`Proxy-Error: ${err}`);
    } catch (_err) {
      // ignore
    }
  };

  /**
   * Replaces all occurrences of the amazon and alexa hosts in the data with the proxy host.
   * It is used to ensure that the URLs in the response point to the proxy server instead of the original amazon or alexa servers.
   * @param data - The data in which to replace the hosts; typically an HTML body or an HTTP location: header.
   * @returns data with replaced hosts
   */
  function replaceHosts(data: string) {
    //const dataOrig = data;
    const amazonRegex = new RegExp(
      `https?://www.${_options.baseAmazonPage}:?[0-9]*/`.replace(/\./g, "\\."),
      "g",
    );
    const alexaRegex = new RegExp(
      `https?://alexa.${_options.baseAmazonPage}:?[0-9]*/`.replace(
        /\./g,
        "\\.",
      ),
      "g",
    );
    data = data.replace(/&#x2F;/g, "/");
    data = data.replace(
      amazonRegex,
      `http://${_options.proxyOwnIp}:${_options.proxyPort}/www.${_options.baseAmazonPage}/`,
    );
    data = data.replace(
      alexaRegex,
      `http://${_options.proxyOwnIp}:${_options.proxyPort}/alexa.${_options.baseAmazonPage}/`,
    );
    //_options.logger && _options.logger('REPLACEHOSTS: ' + dataOrig + ' --> ' + data);
    return data;
  }

  /**
   * This function is used to replace the proxy host back to the original amazon or alexa hosts in the data.
   * It is used to ensure that the URLs in the referer point to the original amazon or alexa servers instead of the proxy server.
   * @param data - The data in which to replace the hosts; typically a referer: HTTP header.
   * @returns data with replaced hosts
   */
  function replaceHostsBack(data: string) {
    const amazonRegex = new RegExp(
      `http://${_options.proxyOwnIp}:${_options.proxyPort}/www.${_options.baseAmazonPage}/`.replace(
        /\./g,
        "\\.",
      ),
      "g",
    );
    const alexaRegex = new RegExp(
      `http://${_options.proxyOwnIp}:${_options.proxyPort}/alexa.${_options.baseAmazonPage}/`.replace(
        /\./g,
        "\\.",
      ),
      "g",
    );
    data = data.replace(amazonRegex, `https://www.${_options.baseAmazonPage}/`);
    data = data.replace(
      alexaRegex,
      `https://alexa.${_options.baseAmazonPage}/`,
    );
    if (data === `http://${_options.proxyOwnIp}:${_options.proxyPort}/`) {
      data = returnedInitUrl;
    }
    return data;
  }

  const onProxyReq: OnProxyReqCallback = (proxyReq, req /*, _res*/) => {
    _options.logger = _options.logger as Logger;

    const url = req.originalUrl || req.url;
    if (
      url.endsWith(".ico") ||
      url.endsWith(".js") ||
      url.endsWith(".ttf") ||
      url.endsWith(".svg") ||
      url.endsWith(".png") ||
      url.endsWith(".appcache")
    )
      return;
    //if (url.startsWith('/ap/uedata')) return;

    logger.debug(`Alexa-Cookie: Proxy-Request: ${req.method} ${url}`);
    //_options.logger && _options.logger('Alexa-Cookie: Proxy-Request-Data: ' + customStringify(proxyReq, null, 2));

    if (typeof proxyReq.getHeader === "function") {
      logger.debug(
        `Alexa-Cookie: Headers ${customStringify(proxyReq.getHeaders(),null,2)}`
      );
      let reqCookie = proxyReq.getHeader("cookie");
      if (reqCookie === undefined) {
        reqCookie = "";
      }
      for (const cookie of Object.keys(initialCookies)) {
        if (
          (typeof reqCookie === "string" || typeof reqCookie === "object") &&
          !reqCookie.includes(`${cookie}=`)
        ) {
          reqCookie += `; ${cookie}=${initialCookies[cookie]}`;
        }
      }
      if (typeof reqCookie === "string" && reqCookie.startsWith("; ")) {
        reqCookie = reqCookie.substr(2);
      }
      proxyReq.setHeader("cookie", reqCookie ?? "");
      if (
        !proxyCookies.length &&
        (typeof reqCookie === "string" || typeof reqCookie === "number")
      ) {
        proxyCookies = `${reqCookie}`;
      } else {
        proxyCookies += `; ${reqCookie}`;
      }
      logger.debug(
        `Alexa-Cookie: Headers ${customStringify(proxyReq.getHeaders(),null,2)}`
      );
    }

    let modified = false;
    if (req.method === "POST") {
      if (
        typeof proxyReq.getHeader === "function" &&
        proxyReq.getHeader("referer")
      ) {
        const referer = proxyReq.getHeader("referer");
        const fixedReferer = replaceHostsBack(referer as string);
        if (fixedReferer) {
          proxyReq.setHeader("referer", fixedReferer);
          logger.debug(
            `Alexa-Cookie: Modify headers: Changed Referer: ${fixedReferer}`,
          );
          modified = true;
        }
      }
      if (
        typeof proxyReq.getHeader === "function" &&
        proxyReq.getHeader("origin") !== `https://${proxyReq.getHeader("host")}`
      ) {
        proxyReq.setHeader("origin", `https://www.${_options.baseAmazonPage}`);
        logger.debug("Alexa-Cookie: Modify headers: Delete Origin");
        modified = true;
      }

      let _postBody = "";
      req.on("data", (chunk) => {
        _postBody += chunk.toString(); // convert Buffer to string
      });
    }
    logger.debug(
      `Alexa-Cookie: Proxy-Request: (modified:${modified})`, sanitizeRequestForLogging(proxyReq)
    );
  };

  const onProxyRes: OnProxyResCallback = (proxyRes, req, res) => {
    const url = req.originalUrl || req.url;
    _options.logger = _options.logger as Logger;

    if (
      url.endsWith(".ico") ||
      url.endsWith(".js") ||
      url.endsWith(".ttf") ||
      url.endsWith(".svg") ||
      url.endsWith(".png") ||
      url.endsWith(".appcache")
    )
      return;
    if (url.startsWith("/ap/uedata")) return;
    //_options.logger && _options.logger('Proxy-Response: ' + customStringify(proxyRes, null, 2));
    let reqestHost = null;
    const proxyResponseSocket = proxyRes.socket as ProxyResponseSocketType;
    if (proxyResponseSocket?._host) reqestHost = proxyResponseSocket._host;
    logger.debug(`Alexa-Cookie: Proxy Response from Host: ${reqestHost}`);
    logger.debug(
      `Alexa-Cookie: Proxy-Response Headers ${customStringify(proxyRes.headers,null,2)}`,
    );
    const sanitizedOutgoing = sanitizeRequestForLogging(
      proxyResponseSocket.parser.outgoing as unknown as http.ClientRequest,
    );
    logger.debug(
      `Alexa-Cookie: Proxy-Response Outgoing ${customStringify(sanitizedOutgoing, null, 2)}`,
    );
    //_options.logger && _options.logger('Proxy-Response RES!!: ' + customStringify(res, null, 2));

    if (proxyRes?.headers?.["set-cookie"]) {
      // make sure cookies are also sent to http by remove secure flags
      for (let i = 0; i < proxyRes.headers["set-cookie"].length; i++) {
        proxyRes.headers["set-cookie"][i] =
          proxyRes.headers["set-cookie"][i]?.replace("Secure", "") ?? "";
      }
      proxyCookies = addCookies(proxyCookies, proxyRes.headers);
    }
    logger.debug(
      `Alexa-Cookie: Cookies handled: ${customStringify(proxyCookies,null,2)}`
    );

    const locationHeader =
      (proxyResponseSocket?.parser?.outgoing?.getHeader(
        "location",
      ) as string) ?? "";

    if (
      (proxyResponseSocket &&
        proxyResponseSocket._host === `www.${_options.baseAmazonPage}` &&
        proxyResponseSocket.parser?.outgoing?.method === "GET" &&
        proxyResponseSocket.parser.outgoing.path?.startsWith(
          "/ap/maplanding",
        )) ||
      locationHeader.includes("/ap/maplanding?") ||
      (proxyRes.headers.location &&
        (proxyRes.headers.location.includes("/ap/maplanding?") ||
          proxyRes.headers.location.includes("/spa/index.html")))
    ) {
      logger.info("Alexa-Cookie: Proxy detected SUCCESS!!");

      const paramStart = (proxyRes.headers.location ?? "").indexOf("?");
      const queryParams = queryStringParse(
        (proxyRes.headers.location ?? "").substr(paramStart + 1),
      );

      proxyRes.statusCode = 302;
      proxyRes.headers.location = `http://${_options.proxyOwnIp}:${_options.proxyPort}/cookie-success`;
      delete proxyRes.headers.referer;

      logger.debug(`Alexa-Cookie: Proxy caught cookie ${customStringify(proxyCookies,null,2)}`)
      logger.debug(
        `Alexa-Cookie: Proxy caught parameters ${customStringify(queryParams, null, 2)}`
      );

      callbackCookieFn?.(null, {
        loginCookie: proxyCookies,
        authorization_code: queryParams["openid.oa2.authorization_code"],
        frc: initialCookies.frc,
        "map-md": initialCookies["map-md"],
        deviceId: deviceId,
        verifier: code_verifier,
      });
      return;
    }

    // If we detect a redirect, rewrite the location header
    if (proxyRes.headers.location) {
      logger.info(
        `Redirect: Original Location ----> ${proxyRes.headers.location}`,
      );
      proxyRes.headers.location = replaceHosts(proxyRes.headers.location);
      if (
        reqestHost &&
        proxyRes.headers.location &&
        proxyRes.headers.location.startsWith("/")
      ) {
        proxyRes.headers.location = `http://${_options.proxyOwnIp}:${_options.proxyPort}/${reqestHost}${proxyRes.headers.location}`;
      }
      logger.info(`Redirect: Final Location ----> ${proxyRes.headers.location}`);
      return;
    }

    modifyResponse(
      res,
      proxyRes?.headers ? proxyRes.headers["content-encoding"] || "" : "",
      (body) => {
        _options.logger = _options.logger as Logger;
        if (body) {
          const bodyOrig = body;
          body = replaceHosts(body);
          if (body !== bodyOrig) {
            logger.debug("Alexa-Cookie: MODIFIED Response Body to rewrite URLs");
          }
        }
        return body;
      },
    );
  };

  const optionsAlexa = {
    target: `https://alexa.${_options.baseAmazonPage}`,
    changeOrigin: true,
    ws: false,
    pathRewrite: {} as Record<string, string>, // enhanced below
    router: router,
    hostRewrite: "true",
    followRedirects: false,
    logLevel: _options.proxyLogLevel,
    onError: onError,
    onProxyRes: onProxyRes,
    onProxyReq: onProxyReq,
    headers: {
      "user-agent":
        "AppleWebKit PitanguiBridge/2.2.485407.0-[HARDWARE=iPhone10_4][SOFTWARE=15.5][DEVICE=iPhone]",
      "accept-language": _options.acceptLanguage,
      authority: `www.${_options.baseAmazonPage}`,
    },
    cookieDomainRewrite: {
      // enhanced below
      "*": "",
    } as Record<string, string>,
  } as Options;

  if (
    optionsAlexa.pathRewrite &&
    typeof optionsAlexa.pathRewrite === "object"
  ) {
    optionsAlexa.pathRewrite[`^/www.${_options.baseAmazonPage}`] = "";
    optionsAlexa.pathRewrite[`^/alexa.${_options.baseAmazonPage}`] = "";
  }
  if (
    optionsAlexa.cookieDomainRewrite &&
    typeof optionsAlexa.cookieDomainRewrite === "object"
  ) {
    optionsAlexa.cookieDomainRewrite[`.${_options.baseAmazonPage}`] =
      _options.proxyOwnIp ?? "127.0.0.1";
    optionsAlexa.cookieDomainRewrite[_options.baseAmazonPage] =
      _options.proxyOwnIp ?? "127.0.0.1";
  }
  optionsAlexa.logProvider = ((defaultProvider) =>
    _options?.logger ?? defaultProvider) as LogProviderCallback;
  // create the proxy (without context)
  const myProxy = proxy("!/cookie-success", optionsAlexa);

  // mount `exampleProxy` in web server
  const app = express();

  app.use(myProxy);
  app.get("/cookie-success", (_req, res) => {
    res.send(_options.proxyCloseWindowHTML);
  });
  if (
    _options.proxyPort &&
    (_options.proxyPort < 1 || _options.proxyPort > 65535)
  ) {
    logger.warn(
      `Alexa-Cookie: Error: Port ${_options.proxyPort} invalid. Using random port.`,
    );
    _options.proxyPort = undefined;
  }
  const server = app
    .listen(
      _options.proxyPort ?? 0,
      _options.proxyListenBind ?? "0.0.0.0",
      () => {
        _options.logger = _options.logger as Logger;
        const addr = server.address();
        const port = typeof addr === "object" ? addr?.port : addr;
        logger.info(`Alexa-Cookie: Proxy-Server listening on port ${port}`);
        callbackListening?.(server);
        callbackListening = null;
      },
    )
    .on("error", (err) => {
      _options.logger = _options.logger as Logger;
      logger.error(`Alexa-Cookie: Proxy-Server Error: ${err}`);
      callbackListening?.(null);
      callbackListening = null;
    });
}

export default { initAmazonProxy };
