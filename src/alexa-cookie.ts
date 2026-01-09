/**
 * partly based on Amazon Alexa Remote Control (PLAIN shell)
 * http://blog.loetzimmer.de/2017/10/amazon-alexa-hort-auf-die-shell-echo.html AND on
 * https://github.com/thorsten-gehrig/alexa-remote-control
 * and much enhanced ...
 */

import type { IncomingHttpHeaders, IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import os from "node:os";
import url from "node:url";
import { parseCookie } from "cookie";
import https from "https";
import querystring from "querystring";
import amazonProxy from "./lib/proxy";
import type {
  AmazonProxyOptions,
  CookieMap,
  ErrorParam,
  Logger,
  ProxyServer,
  RequestCallbackType,
  RequestInfoType,
  RequestOptions,
} from "./types/types";
import { capabilitiesBody } from "./capabilities-body";
import { customStringify } from "./util/customStringify";
import { LoggingFacade } from "./util/LoggingFacade";

const defaultAmazonPage = "amazon.de";
const defaultUserAgent =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36";
const defaultUserAgentLinux =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36";
//const defaultUserAgentMacOs = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/57.0.2987.133 Safari/537.36';
const defaultProxyCloseWindowHTML =
  "<b>Amazon Alexa Cookie successfuly retrieved. You can close the browser.</b>";
const defaultAcceptLanguage = "de-DE";

const apiCallVersion = "2.2.651540.0";
const apiCallUserAgent =
  "AmazonWebView/Amazon Alexa/2.2.651540.0/iOS/18.3.1/iPhone";
const defaultAppName = "ioBroker Alexa2";

const csrfOptions = [
  "/api/language",
  "/spa/index.html",
  "/api/devices-v2/device?cached=false",
  "/templates/oobe/d-device-pick.handlebars",
  "/api/strings",
];

class AlexaCookie {
  generateAlexaCookie: (
    email?: string | null | AmazonProxyOptions | RequestCallbackType,
    password?: string | null | AmazonProxyOptions | RequestCallbackType,
    __options?: AmazonProxyOptions | RequestCallbackType,
    callback?: RequestCallbackType,
  ) => void;
  getDeviceAppName: () => string;
  refreshAlexaCookie: (
    __options: AmazonProxyOptions,
    callback: RequestCallbackType,
  ) => void;
  stopProxyServer: (callback?: RequestCallbackType) => void;

  _logger: Logger = new LoggingFacade(); // defaults to "no-ops"

  constructor() {
    let proxyServer: ProxyServer;

    let _options: AmazonProxyOptions = { logger: new LoggingFacade() };
    // use the configured logger if it's been provided
    this._logger =
      new LoggingFacade({ logger: _options?.logger as Logger }) ?? this._logger;

    let Cookie: string | undefined = "";

    const _self = this;

    const addCookies = (
      Cookie: string | string[] | undefined,
      headers: IncomingHttpHeaders,
    ): string => {
      if (!headers || !headers["set-cookie"]) return Cookie as string;
      const cookies = parseCookie(
        ((Cookie as string[])?.join?.("; ") ?? Cookie) || "",
      );
      let cookie: string | RegExpMatchArray | null;
      for (cookie of headers["set-cookie"]) {
        cookie = cookie.match(/^([^=]+)=([^;]+);.*/);
        if (cookie && cookie.length === 3) {
          if (cookie[1] && cookie[2]) {
            if (cookie[1] === "ap-fid" && cookie[2] === '""') continue;
            if (
              cookie[2] &&
              cookies[cookie[1]] &&
              cookies[cookie[1]] !== cookie[2]
            ) {
              _self._logger.info(
                `Alexa-Cookie: Update Cookie ${cookie[1]} = ${cookie[2]}`,
              );
            } else if (!cookies[cookie[1]]) {
              _self._logger.info(
                `Alexa-Cookie: Add Cookie ${cookie[1]} = ${cookie[2]}`,
              );
            }
            cookies[cookie[1]] = cookie[2];
          }
        }
      }
      Cookie = "" as string;
      for (const name of Object.keys(cookies)) {
        Cookie += `${name}=${cookies[name]}; `;
      }
      Cookie = Cookie.replace(/[; ]*$/, "");
      return Cookie;
    };

    const request = (
      options: RequestOptions,
      infoOrCallback: RequestInfoType | RequestCallbackType,
      callback?: RequestCallbackType,
    ) => {
      _self._logger.debug(
        `Alexa-Cookie: Sending Request with options: ${customStringify(options, null, 2)}`,
      );
      if (typeof infoOrCallback === "function") {
        callback = infoOrCallback;
        infoOrCallback = {
          requests: [],
        } as RequestInfoType;
      }
      let removeContentLength: boolean = false;
      if (options.headers?.["Content-Length"]) {
        if (!options.body) delete options.headers["Content-Length"];
      } else if (options.body) {
        if (!options.headers) options.headers = {};
        options.headers["Content-Length"] = options.body.length;
        removeContentLength = true;
      }

      const req = https.request(options, (res) => {
        let body = "";
        infoOrCallback.requests.push({ options: options, response: res });

        if (
          res.statusCode &&
          options.followRedirects !== false &&
          res.statusCode >= 300 &&
          res.statusCode < 400
        ) {
          _self._logger.debug(
            `Alexa-Cookie: Response (${res.statusCode})${res.headers.location ? ` - Redirect to ${res.headers.location}` : ""}`,
          );
          //options.url = res.headers.location;
          const u = url.parse(res.headers?.location as string);
          if (u.host) options.host = u.host;
          options.path = u.path;
          options.method = "GET";
          options.body = "";
          options.headers.Cookie = Cookie = addCookies(Cookie, res.headers);

          res.socket?.end();
          return request(options, infoOrCallback, callback);
        } else {
          _self._logger.debug(`Alexa-Cookie: Response (${res.statusCode})`);
          res.on("data", (chunk) => {
            body += chunk;
          });

          res.on("end", () => {
            if (removeContentLength) delete options.headers["Content-Length"];
            res.socket?.end();
            callback?.(0, res, body, infoOrCallback);
          });
        }
      });

      req.on("error", (e) => {
        if (typeof callback === "function" && callback.length >= 2) {
          return callback(e, null, null, infoOrCallback);
        }
      });
      if (options?.body) {
        req.write(options.body);
      }
      req.end();
    };

    const getFields = (body: string) => {
      body = body.replace(/[\n\r]/g, " ");
      let re = /^.*?("hidden"\s*name=".*$)/;
      const ar = re.exec(body);
      if (!ar || ar.length < 2) return {};
      re = /.*?name="([^"]+)"[\s^\s]*value="([^"]+).*?"/g;
      const data: Record<string, string> = {};
      let h = re.exec(ar[1] as string);
      while (h !== null) {
        if (h[1] !== "rememberMe") {
          data[h[1] as string] = h[2] as string;
        }
        h = re.exec(ar[1] as string);
      }
      return data;
    };

    const initConfig = () => {
      _options.amazonPage = _options.amazonPage || defaultAmazonPage;
      if (_options.formerRegistrationData?.amazonPage)
        _options.amazonPage = _options.formerRegistrationData.amazonPage;

      _self._logger.info(
        `Alexa-Cookie: Use as Login-Amazon-URL: ${_options.amazonPage}`,
      );

      _options.baseAmazonPage = _options.baseAmazonPage || "amazon.com";
      _self._logger.info(
        `Alexa-Cookie: Use as Base-Amazon-URL: ${_options.baseAmazonPage}`,
      );

      _options.deviceAppName = _options.deviceAppName || defaultAppName;
      _self._logger.info(
        `Alexa-Cookie: Use as Device-App-Name: ${_options.deviceAppName}`,
      );

      if (
        !_options.baseAmazonPageHandle &&
        _options.baseAmazonPageHandle !== ""
      ) {
        const amazonDomain = _options.baseAmazonPage.substr(
          _options.baseAmazonPage.lastIndexOf(".") + 1,
        );
        if (amazonDomain === "jp") {
          _options.baseAmazonPageHandle = `_${amazonDomain}`;
        } else if (amazonDomain !== "com") {
          //_options.baseAmazonPageHandle = '_' + amazonDomain;
          _options.baseAmazonPageHandle = "";
        } else {
          _options.baseAmazonPageHandle = "";
        }
      }

      if (!_options.userAgent) {
        const platform = os.platform();
        if (platform === "win32") {
          _options.userAgent = defaultUserAgent;
        } else {
          /*else if (platform === 'darwin') {
          _options.userAgent = defaultUserAgentMacOs;
      }*/
          _options.userAgent = defaultUserAgentLinux;
        }
      }
      _self._logger.info(
        `Alexa-Cookie: Use as User-Agent: ${_options.userAgent}`,
      );

      _options.acceptLanguage =
        _options.acceptLanguage || defaultAcceptLanguage;

      _self._logger.info(
        `Alexa-Cookie: Use as Accept-Language: ${_options.acceptLanguage}`,
      );

      _options.proxyCloseWindowHTML =
        _options.proxyCloseWindowHTML || defaultProxyCloseWindowHTML;

      if (_options.setupProxy && !_options.proxyOwnIp) {
        _self._logger.info(
          "Alexa-Cookie: Own-IP Setting missing for Proxy. Disabling!",
        );
        _options.setupProxy = false;
      }
      if (_options.setupProxy) {
        _options.setupProxy = true;
        _options.proxyPort = _options.proxyPort || 0;
        _options.proxyListenBind = _options.proxyListenBind || "0.0.0.0";
        _self._logger.info(
          `Alexa-Cookie: Proxy-Mode enabled if needed: ${_options.proxyOwnIp}:${_options.proxyPort} to listen on ${_options.proxyListenBind}`,
        );
      } else {
        _options.setupProxy = false;
        _self._logger.info("Alexa-Cookie: Proxy mode disabled");
      }
      _options.proxyLogLevel = _options.proxyLogLevel || "warn";
      _options.amazonPageProxyLanguage =
        _options.amazonPageProxyLanguage || "de_DE";

      if (_options.formerRegistrationData) _options.proxyOnly = true;
    };

    const getCSRFFromCookies = (
      cookie: string | string[] | undefined,
      _options: AmazonProxyOptions,
      callback: RequestCallbackType,
    ) => {
      // get CSRF
      const csrfUrls = csrfOptions;

      function csrfTry() {
        const path = csrfUrls.shift();
        const options = {
          host: `alexa.${_options.amazonPage}`,
          path: path,
          method: "GET",
          headers: {
            DNT: "1",
            "User-Agent": _options.userAgent,
            Connection: "keep-alive",
            Referer: `https://alexa.${_options.amazonPage}/spa/index.html`,
            Cookie: cookie,
            Accept: "*/*",
            Origin: `https://alexa.${_options.amazonPage}`,
          },
        };

        _self._logger.debug(`Alexa-Cookie: Step 4: get CSRF via ${path}`);
        request(
          options,
          (_error: ErrorParam, response: IncomingMessage) => {
            cookie = addCookies(cookie, response?.headers ?? null);
            const ar = /csrf=([^;]+)/.exec(cookie);
            const csrf = ar ? ar[1] : undefined;
            _self._logger.info(
              `Alexa-Cookie: Result: csrf=${csrf}, Cookie=${cookie}`,
            );
            if (!csrf && csrfUrls.length) {
              csrfTry();
              return;
            }
            callback?.(null, {
              cookie: cookie,
              csrf: csrf,
            });
          },
          undefined,
        );
      }

      csrfTry();
    };

    this.generateAlexaCookie = (
      email?: string | null | AmazonProxyOptions | RequestCallbackType,
      password?: string | null | AmazonProxyOptions | RequestCallbackType,
      __options?: AmazonProxyOptions | RequestCallbackType,
      callback?: RequestCallbackType,
    ) => {
      if (__options && Object.hasOwn(__options, "logger")) {
        _self._logger = (__options as AmazonProxyOptions).logger as Logger;
      }

      // == optional parameter shifting ==
      if (email !== undefined && typeof email !== "string") {
        /*        @ts-expect-error ts-2322 - (mismatching types) we're parameter-shifting, this is normal  */
        callback = __options;
        /*        @ts-expect-error ts-2322 */
        __options = password;
        password = email;
        email = null;
      }
      if (password !== undefined && typeof password !== "string") {
        /*        @ts-expect-error ts-2322 */
        callback = __options;
        /*        @ts-expect-error ts-2322 */
        __options = password;
        password = null;
      }

      if (typeof __options === "function") {
        callback = __options;
        __options = {};
      }
      // == end of parameter shifting ==

      _options = __options as AmazonProxyOptions;

      if (!email || !password) {
        _options.proxyOnly = true;
      }

      initConfig();

      function prepareResult(err: ErrorParam, data: CookieMap) {
        if (err || !data.authorization_code) {
          callback?.(err, data.loginCookie);
          return;
        }
        handleTokenRegistration(_options, data, callback ?? (() => {}));
      }

      if (!_options.proxyOnly) {
        // get first cookie and write redirection target into referer
        const options = {
          host: `alexa.${_options.amazonPage}`,
          path: "",
          method: "GET",
          headers: {
            DNT: "1",
            "Upgrade-Insecure-Requests": "1",
            "User-Agent": _options.userAgent,
            "Accept-Language": _options.acceptLanguage,
            Connection: "keep-alive",
            Accept: "*/*",
          },
        };
        _self._logger.debug(
          "Alexa-Cookie: Step 1: get first cookie and authentication redirect",
        );
        request(
          options,
          (
            error: ErrorParam,
            response: IncomingMessage,
            body: string | Record<string, string>,
            info,
          ) => {
            if (error) {
              callback?.(error, null);
              return;
            }

            const lastRequestOptions =
              info.requests[info.requests.length - 1].options;
            // login empty to generate session
            Cookie = addCookies(Cookie, response.headers);
            const options: RequestOptions = {
              host: `www.${_options.amazonPage}`,
              path: "/ap/signin",
              method: "POST",
              headers: {
                DNT: "1",
                "Upgrade-Insecure-Requests": "1",
                "User-Agent": _options.userAgent,
                "Accept-Language": _options.acceptLanguage,
                Connection: "keep-alive",
                "Content-Type": "application/x-www-form-urlencoded",
                Referer: `https://${lastRequestOptions.host}${lastRequestOptions.path}`,
                Cookie: Cookie,
                Accept: "*/*",
              },
              gzip: true,
              body: querystring.stringify(getFields(body as string)) as string,
            };
            _self._logger.debug(
              "Alexa-Cookie: Step 2: login empty to generate session",
            );
            request(
              options,
              (error: ErrorParam, response: IncomingMessage, body: string) => {
                if (error) {
                  callback?.(error, null);
                  return;
                }

                // login with filled out form
                //  !!! referer now contains session in URL
                options.host = `www.${_options.amazonPage}`;
                options.path = "/ap/signin";
                options.method = "POST";
                options.headers.Cookie = Cookie = addCookies(
                  Cookie,
                  response.headers,
                );
                const ar = options.headers.Cookie.match(/session-id=([^;]+)/);
                options.headers.Referer = `https://www.${_options.amazonPage}/ap/signin/${ar?.[1]}`;
                options.body = getFields(body);
                options.body.email = email || "";
                options.body.password = password || "";
                options.body = querystring.stringify(
                  options.body,
                  undefined,
                  undefined,
                  {
                    encodeURIComponent: encodeURIComponent,
                  },
                );

                _self._logger.debug(
                  "Alexa-Cookie: Step 3: login with filled form, referer contains session id",
                );
                request(
                  options,
                  (
                    error: ErrorParam,
                    _response: IncomingMessage,
                    body,
                    info,
                  ) => {
                    if (error) {
                      callback?.(error, null);
                      return;
                    }

                    const lastRequestOptions =
                      info.requests[info.requests.length - 1].options;

                    // check whether the login has been successful or exit otherwise
                    if (
                      !lastRequestOptions.host.startsWith("alexa") ||
                      !lastRequestOptions.path.endsWith(".html")
                    ) {
                      let errMessage =
                        "Login unsuccessful. Please check credentials.";
                      const amazonMessage = body.match(
                        /auth-warning-message-box[\S\s]*"a-alert-heading">([^<]*)[\S\s]*<li><[^>]*>\s*([^<\n]*)\s*</,
                      );
                      if (amazonMessage?.[1] && amazonMessage[2]) {
                        errMessage = `Amazon-Login-Error: ${amazonMessage[1]}: ${amazonMessage[2]}`;
                      }
                      if (_options.setupProxy) {
                        if (proxyServer) {
                          errMessage += ` Please open http://${_options.proxyOwnIp}:${_options.proxyPort}/ with your browser and login to Amazon. The cookie will be output here after successful login.`;
                        } else {
                          amazonProxy.initAmazonProxy(
                            _options,
                            prepareResult,
                            (server: ProxyServer) => {
                              if (!server) {
                                return callback?.(
                                  new Error("Proxy could not be initialized"),
                                  null,
                                );
                              }
                              proxyServer = server;
                              if (
                                !_options.proxyPort ||
                                _options.proxyPort === 0
                              ) {
                                _options.proxyPort = (
                                  proxyServer.address() as AddressInfo
                                )?.port;
                              }
                              errMessage += ` Please open http://${_options.proxyOwnIp}:${_options.proxyPort}/ with your browser and login to Amazon. The cookie will be output here after successful login.`;
                              callback?.(new Error(errMessage), null);
                            },
                          );
                          return;
                        }
                      }
                      callback?.(new Error(errMessage), null);
                      return;
                    }

                    return getCSRFFromCookies(
                      Cookie,
                      _options,
                      callback as RequestCallbackType,
                    );
                  },
                );
              },
            );
          },
        );
      } else {
        amazonProxy.initAmazonProxy(
          _options,
          prepareResult,
          (server: ProxyServer) => {
            if (!server) {
              callback?.(
                new Error("Proxy Server could not be initialized. Check Logs."),
                null,
              );
              return;
            }
            proxyServer = server;
            if (!_options.proxyPort || _options.proxyPort === 0) {
              _options.proxyPort = (proxyServer.address() as AddressInfo)?.port;
            }
            const errMessage = `Please open http://${_options.proxyOwnIp}:${_options.proxyPort}/ with your browser and login to Amazon. The cookie will be output here after successful login.`;
            callback?.(new Error(errMessage), null);
          },
        );
      }
    };

    this.getDeviceAppName = () => {
      return _options?.deviceAppName || defaultAppName;
    };

    const handleTokenRegistration = (
      _options: AmazonProxyOptions,
      loginData: CookieMap,
      callback: RequestCallbackType,
    ) => {
      if (_options && Object.hasOwn(_options, "logger")) {
        _self._logger = _options.logger as Logger;
      }
      _self._logger.debug(
        `Handle token registration Start: ${customStringify(loginData, null, 2)}`,
      );

      loginData.deviceAppName = _options.deviceAppName;

      let deviceSerial: string;
      if (
        !_options.formerRegistrationData ||
        !_options.formerRegistrationData.deviceSerial
      ) {
        const deviceSerialBuffer = Buffer.alloc(16);
        for (let i = 0; i < 16; i++) {
          deviceSerialBuffer.writeUInt8(Math.floor(Math.random() * 255), i);
        }
        deviceSerial = deviceSerialBuffer.toString("hex");
      } else {
        _self._logger.info("Proxy Init: reuse deviceSerial from former data");
        deviceSerial = _options.formerRegistrationData.deviceSerial;
      }
      loginData.deviceSerial = deviceSerial;

      const cookies = parseCookie(loginData.loginCookie ?? "");
      Cookie = loginData.loginCookie;

      /*
          Register App
       */

      const registerData = {
        requested_extensions: ["device_info", "customer_info"],
        cookies: {
          website_cookies: [] as { Value: string | undefined; Name: string }[],
          domain: `.${_options.baseAmazonPage}`,
        },
        registration_data: {
          domain: "Device",
          app_version: apiCallVersion,
          device_type: "A2IVLV5VM2W81",
          device_name: `%FIRST_NAME%\u0027s%DUPE_STRATEGY_1ST%${_options.deviceAppName}`,
          os_version: "18.3.1",
          device_serial: deviceSerial,
          device_model: "iPhone",
          app_name: _options.deviceAppName,
          software_version: "1",
        },
        auth_data: {
          // Filled below
        },
        user_context_map: {
          frc: cookies.frc,
        },
        requested_token_type: ["bearer", "mac_dms", "website_cookies"],
      };
      if (loginData.accessToken) {
        registerData.auth_data = {
          access_token: loginData.accessToken,
        };
      } else if (loginData.authorization_code && loginData.verifier) {
        registerData.auth_data = {
          client_id: loginData.deviceId,
          authorization_code: loginData.authorization_code,
          code_verifier: loginData.verifier,
          code_algorithm: "SHA-256",
          client_domain: "DeviceLegacy",
        };
      }
      for (const key of Object.keys(cookies)) {
        registerData.cookies.website_cookies.push({
          Value: cookies[key],
          Name: key,
        });
      }

      const options = {
        host: `api.${_options.baseAmazonPage}`,
        path: "/auth/register",
        method: "POST",
        headers: {
          "User-Agent": apiCallUserAgent,
          "Accept-Language": _options.acceptLanguage,
          "Accept-Charset": "utf-8",
          Connection: "keep-alive",
          "Content-Type": "application/json",
          Cookie: loginData.loginCookie,
          Accept: "application/json",
          "x-amzn-identity-auth-domain": `api.${_options.baseAmazonPage}`,
        },
        body: JSON.stringify(registerData),
      };
      _self._logger.debug("Alexa-Cookie: Register App");
      _self._logger.debug(
        `Alexa-Cookie: Options= ${customStringify(options, null, 2)}`,
      );
      request(
        options,
        (
          error: ErrorParam,
          response: IncomingMessage,
          body: Record<string, string> & {
            response: {
              success: {
                tokens: {
                  bearer: {
                    refresh_token: string;
                    access_token: string;
                  };
                  mac_dms: string;
                  website_cookies: string;
                };
              };
            };
          },
        ) => {
          if (error) {
            callback?.(error, null);
            return;
          }
          try {
            if (typeof body !== "object") body = JSON.parse(body);
          } catch (err) {
            _self._logger.error(
              `Register App Response: ${customStringify(body, null, 2)}`,
            );
            _self._logger.error(err);
            callback?.(err, null);
            return;
          }
          _self._logger.debug(
            `Register App Response: ${customStringify(body, null, 2)}`,
          );

          if (
            !body.response ||
            !body.response.success ||
            !body.response.success.tokens ||
            !body.response.success.tokens.bearer
          ) {
            callback?.(new Error("No tokens in Register response"), null);
            return;
          }
          Cookie = addCookies(Cookie, response.headers);
          loginData.refreshToken =
            body.response.success.tokens.bearer.refresh_token;
          const accessToken = body.response.success.tokens.bearer.access_token;
          loginData.tokenDate = Date.now();
          loginData.macDms = body.response.success.tokens.mac_dms;

          if (
            body.response.success.tokens.website_cookies &&
            Array.isArray(body.response.success.tokens.website_cookies)
          ) {
            const newCookies = [] as string[];
            body.response.success.tokens.website_cookies.forEach((cookie) => {
              newCookies.push(`${cookie.Name}=${cookie.Value}; `);
            });
            Cookie = addCookies(Cookie, { "set-cookie": newCookies });
          }

          registerTokenCapabilities(accessToken, () => {
            /*
              Get Amazon Marketplace Country
          */

            const options = {
              host: `alexa.${_options.baseAmazonPage}`,
              path: `/api/users/me?platform=ios&version=${apiCallVersion}`,
              method: "GET",
              headers: {
                "User-Agent": apiCallUserAgent,
                "Accept-Language": _options.acceptLanguage,
                "Accept-Charset": "utf-8",
                Connection: "keep-alive",
                Accept: "application/json",
                Cookie: Cookie,
              },
            };
            _self._logger.debug("Alexa-Cookie: Get User data");
            _self._logger.debug(
              `Options: ${customStringify(options, null, 2)}`,
            );
            request(
              options,
              (error: ErrorParam, response: IncomingMessage, body) => {
                if (!error) {
                  const statusCode = response?.statusCode as number;
                  if (!(200 <= statusCode) && statusCode <= 299) {
                    // not ok
                    _self._logger.error(
                      `Get User data Response: ${customStringify(body, null, 2)}`,
                    );
                    _self._logger.error(
                      `      response headers: ${customStringify(response.headers, null, 2)}`,
                    );
                    callback?.(
                      new Error(
                        `Getting user data failed with status code ${statusCode}`,
                      ),
                      null,
                    );
                    return;
                  } else {
                    try {
                      if (typeof body !== "object") body = JSON.parse(body);
                    } catch (err) {
                      _self._logger.error(
                        `Get User data Response: ${customStringify(body, null, 2)}`,
                      );
                      _self._logger.error(
                        `      response headers: ${customStringify(response.headers, null, 2)}`,
                      );
                      _self._logger.error(err);
                      callback?.(err, null);
                      return;
                    }
                    _self._logger.debug(
                      `Get User data Response:${customStringify(body, null, 2)}`,
                    );

                    Cookie = addCookies(Cookie, response.headers);

                    if (body.marketPlaceDomainName) {
                      const pos = body.marketPlaceDomainName.indexOf(".");
                      if (pos !== -1)
                        _options.amazonPage = body.marketPlaceDomainName.substr(
                          pos + 1,
                        );
                    }
                    loginData.amazonPage = _options.amazonPage;
                  }
                } else if (error && (!_options || !_options.amazonPage)) {
                  callback?.(error, null);
                  return;
                } else if (
                  error &&
                  (!_options.formerRegistrationData ||
                    !_options.formerRegistrationData.amazonPage) &&
                  _options.amazonPage
                ) {
                  _self._logger.debug(
                    `Continue with externally set amazonPage: ${_options.amazonPage} `,
                  );
                } else if (error) {
                  _self._logger.warn(
                    "Ignore error while getting user data and amazonPage because previously set amazonPage is available",
                  );
                }

                loginData.loginCookie = Cookie;

                getLocalCookies(
                  loginData.amazonPage,
                  loginData.refreshToken,
                  (err: ErrorParam, localCookie) => {
                    if (err) {
                      callback?.(err, null);
                    }

                    loginData.localCookie = localCookie;
                    getCSRFFromCookies(
                      loginData.localCookie,
                      _options,
                      (err: ErrorParam, resData) => {
                        if (err) {
                          callback?.(
                            new Error(
                              `Error getting csrf for ${loginData.amazonPage}`,
                            ),
                            null,
                          );
                          return;
                        }
                        loginData.localCookie = resData.cookie;
                        loginData.csrf = resData.csrf;
                        delete loginData.accessToken;
                        delete loginData.authorization_code;
                        delete loginData.verifier;
                        loginData.dataVersion = 2;
                        _self._logger.info(
                          `Final Registration Result: ${customStringify(loginData, null, 2)} `,
                        );
                        callback?.(null, loginData);
                      },
                    );
                  },
                );
              },
            );
          });
        },
      );
    };

    const registerTokenCapabilities = (
      accessToken: string,
      callback: RequestCallbackType,
    ) => {
      /*
          Register Capabilities - mainly needed for HTTP/2 push infos
       */
      const options = {
        host: `api.amazonalexa.com`, // How Domains needs to be for other regions? au/jp?
        path: `/v1/devices/@self/capabilities`,
        method: "PUT",
        headers: {
          "User-Agent": apiCallUserAgent,
          "Accept-Language": _options.acceptLanguage,
          "Accept-Charset": "utf-8",
          Connection: "keep-alive",
          "Content-type": "application/json; charset=UTF-8",
          authorization: `Bearer ${accessToken}`,
        },
        body: JSON.stringify(capabilitiesBody),

        // New
        // {"envelopeVersion":"20160207","legacyFlags":{"SUPPORTS_TARGET_PLATFORM":"TABLET","SUPPORTS_SECURE_LOCKSCREEN":false,"SUPPORTS_DATAMART_NAMESPACE":"Vox","AXON_SUPPORT":true,"SUPPORTS_DROPIN_OUTBOUND":true,"SUPPORTS_LYRICS_IN_CARD":false,"VOICE_PROFILE_SWITCHING_DISABLED":true,"SUPPORTS_ARBITRATION":true,"SUPPORTS_HOME_AUTOMATION":true,"SUPPORTS_KEYS_IN_HEADER":false,"SUPPORTS_TTS_SPEECHMARKS":true,"AUDIO_PLAYER_SUPPORTS_TTS_URLS":false,"SUPPORTS_SIP_OUTBOUND_CALLING":true,"SUPPORTS_MIXING_BEHAVIOR_FOR_AUDIO_PLAYER":false,"SUPPORTS_COMMS":true,"SCREEN_WIDTH":1170,"SUPPORTS_VIDEO_CALLING":true,"FRIENDLY_NAME_TEMPLATE":"VOX","SUPPORTS_PFM_CHANGED":true,"SPEECH_SYNTH_SUPPORTS_TTS_URLS":false,"SUPPORTS_SCRUBBING":true},"capabilities":[{"type":"AlexaInterface","interface":"AudioPlayer","version":"1.3"},{"version":"1.0","type":"AlexaInterface","interface":"Settings"},{"interface":"System","type":"AlexaInterface","version":"1.0"},{"type":"AlexaInterface","interface":"AudioActivityTracker","version":"1.0"},{"interface":"SpeechRecognizer","version":"2.3","type":"AlexaInterface"},{"type":"AlexaInterface","interface":"Speaker","version":"1.0"},{"type":"AlexaInterface","version":"1.0","interface":"SpeechSynthesizer"},{"type":"AlexaInterface","version":"0.1","interface":"CardRenderer"},{"interface":"PlaybackController","type":"AlexaInterface","version":"1.0"},{"version":"1.1","type":"AlexaInterface","interface":"Navigation"},{"version":"1.1","type":"AlexaInterface","interface":"InteractionModel"},{"type":"AlexaInterface","version":"1.1","interface":"Geolocation"}]}
      };
      _self._logger.debug("Alexa-Cookie: Register capabilities");
      _self._logger.debug(options);
      request(options, (error, response, body) => {
        if (
          error ||
          (response.statusCode !== 204 && response.statusCode !== 200)
        ) {
          _self._logger.error(
            "Alexa-Cookie: Could not set capabilities, Push connection might not work!",
          );
          _self._logger.error(
            `Alexa - Cookie: Error: BODY: ${customStringify(body, null, 2)}`,
          );
          _self._logger.error(error);
        }
        callback?.();
      });
    };

    const getLocalCookies = (
      amazonPage?: string,
      refreshToken?: string,
      callback?: RequestCallbackType,
    ) => {
      Cookie = ""; // Reset because we are switching domains
      /*
          Token Exchange to Amazon Country Page
      */

      const exchangeParams = {
        "di.os.name": "iOS",
        app_version: apiCallVersion,
        domain: `.${amazonPage}`,
        source_token: refreshToken,
        requested_token_type: "auth_cookies",
        source_token_type: "refresh_token",
        "di.hw.version": "iPhone",
        "di.sdk.version": "6.12.4",
        app_name: _options.deviceAppName || defaultAppName,
        "di.os.version": "16.6",
      };
      const options = {
        host: `www.${amazonPage}`,
        path: "/ap/exchangetoken/cookies",
        method: "POST",
        headers: {
          "User-Agent": apiCallUserAgent,
          "Accept-Language": _options.acceptLanguage,
          "Accept-Charset": "utf-8",
          Connection: "keep-alive",
          "Content-Type": "application/x-www-form-urlencoded",
          Accept: "*/*",
          Cookie: Cookie,
          "x-amzn-identity-auth-domain": `api.${amazonPage}`,
        },
        body: querystring.stringify(exchangeParams, undefined, undefined, {
          encodeURIComponent: encodeURIComponent,
        }),
      };
      _self._logger.debug(`Alexa - Cookie: Exchange tokens for ${amazonPage}`);
      _self._logger.debug(options);

      request(options, (error: ErrorParam, response: IncomingMessage, body) => {
        if (error) {
          callback?.(error, null);
          return;
        }
        try {
          if (typeof body !== "object") body = JSON.parse(body);
        } catch (err) {
          _self._logger.error(
            `Exchange Token Response: ${customStringify(body, null, 2)}`,
          );
          callback?.(err, null);
          return;
        }
        _self._logger.debug(
          `Exchange Token Response: ${customStringify(body, null, 2)}`,
        );

        if (
          !body.response ||
          !body.response.tokens ||
          !body.response.tokens.cookies
        ) {
          callback?.(new Error("No cookies in Exchange response"), null);
          return;
        }
        if (!body.response.tokens.cookies[`.${amazonPage}`]) {
          callback?.(
            new Error(`No cookies for ${amazonPage} in Exchange response`),
            null,
          );
          return;
        }

        Cookie = addCookies(Cookie, response.headers);
        const cookies = parseCookie(Cookie);
        body.response.tokens.cookies[`.${amazonPage}`].forEach(
          (cookie: { Name: string; Value: string }) => {
            if (cookies[cookie.Name] && cookies[cookie.Name] !== cookie.Value) {
              _self._logger.info(
                `Alexa - Cookie: Update Cookie ${cookie.Name} = ${cookie.Value} `,
              );
            } else if (!cookies[cookie.Name]) {
              _self._logger.info(
                `Alexa - Cookie: Add Cookie ${cookie.Name} = ${cookie.Value} `,
              );
            }
            cookies[cookie.Name] = cookie.Value;
          },
        );
        let localCookie = "";
        for (const name of Object.keys(cookies)) {
          localCookie += `${name}=${cookies[name]}; `;
        }
        localCookie = localCookie.replace(/[; ]*$/, "");

        callback?.(null, localCookie);
      });
    };

    this.refreshAlexaCookie = (
      __options: AmazonProxyOptions,
      callback: RequestCallbackType,
    ) => {
      if (__options && Object.hasOwn(__options, "logger")) {
        _self._logger = (__options as AmazonProxyOptions).logger as Logger;
      }

      if (
        !__options ||
        !__options.formerRegistrationData ||
        !__options.formerRegistrationData.loginCookie ||
        !__options.formerRegistrationData.refreshToken
      ) {
        callback?.(
          new Error("No former registration data provided for Cookie Refresh"),
          null,
        );
        return;
      }

      if (typeof __options === "function") {
        callback = __options;
        __options = {};
      }

      _options = __options;

      __options.proxyOnly = true;

      initConfig();

      _options.formerRegistrationData = _options.formerRegistrationData ?? {};
      const refreshData = {
        app_name: _options.deviceAppName || defaultAppName,
        app_version: apiCallVersion,
        "di.sdk.version": "6.12.4",
        source_token: _options.formerRegistrationData.refreshToken,
        package_name: "com.amazon.echo",
        "di.hw.version": "iPhone",
        platform: "iOS",
        requested_token_type: "access_token",
        source_token_type: "refresh_token",
        "di.os.name": "iOS",
        "di.os.version": "16.6",
        current_version: "6.12.4",
      };

      const options = {
        host: `api.${_options.baseAmazonPage}`,
        path: "/auth/token",
        method: "POST",
        headers: {
          "User-Agent": apiCallUserAgent,
          "Accept-Language": _options.acceptLanguage,
          "Accept-Charset": "utf-8",
          Connection: "keep-alive",
          "Content-Type": "application/x-www-form-urlencoded",
          Cookie: _options.formerRegistrationData.loginCookie,
          Accept: "application/json",
          "x-amzn-identity-auth-domain": `api.${_options.baseAmazonPage}`,
        },
        body: querystring.stringify(refreshData),
      };
      Cookie = _options.formerRegistrationData.loginCookie;
      _self._logger.info("Alexa-Cookie: Refresh Token");
      _self._logger.debug(options);
      request(options, (error, response, body) => {
        if (error) {
          callback?.(error, null);
          return;
        }
        try {
          if (typeof body !== "object") body = JSON.parse(body);
        } catch (err) {
          _self._logger.error(
            `Refresh Token Response: ${customStringify(body, null, 2)}`,
          );
          callback?.(err, null);
          return;
        }
        _self._logger.debug(
          `Refresh Token Response: ${customStringify(body, null, 2)}`,
        );
        _options.formerRegistrationData = _options.formerRegistrationData ?? {};

        _options.formerRegistrationData.loginCookie = addCookies(
          _options.formerRegistrationData.loginCookie,
          response.headers,
        );

        if (!body.access_token) {
          _options.logger?.debug(
            "ERROR: No new access token in Refresh Token response",
          );
          callback?.(
            new Error("No new access token in Refresh Token response"),
            null,
          );
          return;
        }
        _options.formerRegistrationData.loginCookie = addCookies(
          Cookie,
          response.headers,
        );
        _options.formerRegistrationData.accessToken = body.access_token;

        getLocalCookies(
          _options.baseAmazonPage ?? "amazon.com",
          _options.formerRegistrationData?.refreshToken,
          (err, comCookie) => {
            _options.formerRegistrationData =
              _options.formerRegistrationData ?? {};

            if (err) {
              _options.logger?.error(err);
              callback?.(err, null);
            }

            // Restore frc and map-md
            const initCookies = parseCookie(
              _options.formerRegistrationData?.loginCookie ?? "",
            );
            let newCookie = `frc=${initCookies.frc}; `;
            newCookie += `map-md=${initCookies["map-md"]}; `;
            newCookie += comCookie;

            _options.formerRegistrationData.loginCookie = newCookie;
            handleTokenRegistration(
              _options,
              _options.formerRegistrationData,
              callback,
            );
          },
        );
      });
    };

    this.stopProxyServer = (callback?: RequestCallbackType) => {
      if (proxyServer) {
        proxyServer.close(() => {
          callback?.();
        });
      }
      proxyServer = null;
    };
  }
}

export default new AlexaCookie();
