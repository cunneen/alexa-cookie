import alexaCookie from "../alexa-cookie";
import type { AmazonProxyOptions } from "../types/types";

import { config } from "./config";
import { loadResult } from "./util/loadResult";
import { saveResult } from "./util/saveResult";

// You can explicitly set `config.formerRegistratinData` here, otherwise it will use the file in the configured location (i.e. `config.formerDataStorePath`, which defaults to "<project dir>/data/formerDataStore.json")
// config.formerRegistrationData = {
//   /* ... */
// } // required: provide the result object from previous proxy usages here and some generated data will be reused for next proxy call too

const logger = config.logger ?? console;

// Load former data store from file if existing and not provided in config
config.formerRegistrationData = loadFormerDataStore(config);

// ==== REFRESH ALEXA COOKIE ====
alexaCookie.refreshAlexaCookie(config, (err, result) => {
  if (err) {
    logger.error(`RESULT: ${err} / ${JSON.stringify(result, null, 2)}`);
    logger.error(err);
  } else {
    logger.info(`RESULT: ${JSON.stringify(result, null, 2)}`);
    saveResult(result, config);
  }
});

function loadFormerDataStore(config: AmazonProxyOptions) {
  if (!config.formerRegistrationData) {
    try {
      logger.info(
        `Refresh Init: loaded registration data from file ${config.formerDataStorePath}`,
      );
      return loadResult(config);
    } catch (e: unknown) {
      logger.error(
        `Refresh Init: could not load registration data from file ${config.formerDataStorePath}`,
      );
      logger.error(e);
    }
  } else {
    logger.info(`Refresh Init: registration data provided in config`);
    return config.formerRegistrationData;
  }
}
