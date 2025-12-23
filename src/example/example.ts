import alexaCookie from "../alexa-cookie";
import { config } from "./config";

try {
  alexaCookie.generateAlexaCookie(
    /*'amazon@email.de', 'amazon-password',*/ config,
    (err, result) => {
      if (err) {
        (config.logger ?? console).error(
          `RESULT: ${err} / ${JSON.stringify(result)}`,
        );
      }
      if (result?.loginCookie) {
        alexaCookie.stopProxyServer();
      }
    },
  );
} catch (e) {
  const logger = config.logger ?? console;
  logger.error("ERROR in example:");
  logger.error(e);
} finally {
  // flush logs
  if (config.logger?.flush) {
    config.logger.flush();
  }
}
