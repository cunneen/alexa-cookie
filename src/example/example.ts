import alexaCookie from "../alexa-cookie";
import { config } from "./config";
import { saveResult } from "./util/saveResult";

const logger = config.logger ?? console;

try {
  alexaCookie.generateAlexaCookie(
    /*'amazon@email.de', 'amazon-password',*/ config,
    (err, result) => {
      if (err) {
        logger.error(`RESULT: ${err} / ${JSON.stringify(result, null, 2)}`);
      } else if (result) {
        if (result?.csrf) {
          alexaCookie.stopProxyServer();
        }
        saveResult(result, config);
        logger.info(`RESULT: ${JSON.stringify(result, null, 2)}`);
      }
    },
  );
} catch (e) {
  logger.error("ERROR in example:");
  logger.error(e);
} finally {
  // flush logs
  if (config.logger?.flush) {
    config.logger.flush();
  }
}
