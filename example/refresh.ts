/* jshint -W097 */
/* jshint -W030 */
/* jshint strict: false */
/* jslint node: true */
/* jslint esversion: 6 */

import alexaCookie from "../alexa-cookie";

import type { AmazonProxyOptions } from "../lib/types";

const config: AmazonProxyOptions = {
  logger: console,
  formerRegistrationData: {
    /* ... */
  }, // required: provide the result object from subsequent proxy usages here and some generated data will be reused for next proxy call too
} as AmazonProxyOptions;

alexaCookie.refreshAlexaCookie(config, (err, result) => {
  console.log(`RESULT: ${err} / ${JSON.stringify(result)}`);
});
