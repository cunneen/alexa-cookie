import path from "node:path";
import type { AmazonProxyOptions } from "../types/types";
import { getLogger } from "./logging/getLogger";

// local date/time as 'YYYY-MM-DDTHH:MM' e.g. '2025-12-11T12:02'
const dateString = new Date(
  Date.now() - 1000 * 60 * new Date().getTimezoneOffset(),
)
  .toISOString()
  .substring(0, 16);
export const config: AmazonProxyOptions = {
  logger: getLogger({
    level: "debug",
    outputConsoleLevel: "debug",
    outputConsolePretty: true,
    outputLogFileLevel: "debug",
    outputLogFilePath: path.join(
      __dirname,
      `../../logs/example_${dateString}.log.jsonl`,
    ),
  }),
  proxyOwnIp: "127.0.0.1", // required if proxy enabled: provide the own IP with which you later access the proxy.
  // proxyOwnIp: "10.144.29.163", // required if proxy enabled: provide the own IP with which you later access the proxy.
  // Providing/Using a hostname here can lead to issues!
  // Needed to set up all rewriting and proxy stuff internally

  // The following options are optional. Try without them first and just use really needed ones!!

  amazonPage: "amazon.com.au", // optional: possible to use with different countries, default is 'amazon.de'
  acceptLanguage: "en-AU", // optional: webpage language, should match to amazon-Page, default is 'de-DE'
  //userAgent: '...',          // optional: own userAgent to use for all request, overwrites default one, should not be needed
  // proxyOnly: true,           // optional: should only the proxy method be used? When no email/password are provided this will set to true automatically, default: false
  // setupProxy: true,          // optional: should the library setup a proxy to get cookie when automatic way did not worked? Default false!
  proxyPort: 53290, // optional: use this port for the proxy, default is 0 means random port is selected
  // proxyListenBind: '0.0.0.0',// optional: set this to bind the proxy to a special IP, default is '0.0.0.0'
  proxyLogLevel: "debug", // optional: Loglevel of Proxy, default 'warn'
  // baseAmazonPage: 'amazon.com.au', // optional: Change the Proxy Amazon Page - all "western countries" directly use amazon.com including australia! Change to amazon.co.jp for Japan
  amazonPageProxyLanguage: "en_AU", // optional: language to be used for the Amazon Sign-in page the proxy calls. default is "de_DE")
  //deviceAppName: '...',       // optional: name of the device app name which will be registered with Amazon, leave empty to use a default one
  formerDataStorePath: path.join(__dirname, "../../data/formerDataStore.json"), // optional: overwrite path where some of the formerRegistrationData are persisted to optimize against Amazon security measures. Defaults to "<project dir>/data/formerDataStore.json"
  //formerRegistrationData: { ... }, // optional/preferred: provide the result object from previous proxy usages here and some generated data will be reused for next proxy call too
  //proxyCloseWindowHTML: '...' //  optional: use in order to override the default html displayed when the proxy window can be closed, default is '<b>Amazon Alexa Cookie successfully retrieved. You can close the browser.</b>'
} as AmazonProxyOptions;
