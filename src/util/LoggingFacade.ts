import { default as noopLogger } from "abstract-logging";
import type { Logger, LoggerFunction } from "../types/types";

/**
 * A Facade for loggers, which defaults to "no-op" for each of its logging functions but
 * can easiliy be replaced with an alternative implementation.
 * @example
 * ```js
 * // this uses "console" for all logging operations
 * import { LoggingFacade } from './util/LoggingFacade'
 *
 * const myLogger = new LoggingFacade({logger: console})
 * myLogger.log("default log level")
 * myLogger.error(new Error("I threw an error"))
 * ```
 */
export class LoggingFacade implements Logger {
  _implementation: Logger = noopLogger; // provides no-ops for all the log functions

  // delegate our log functions to the implementation (at runtime)
  log: LoggerFunction = (...args) => {
    // use "info" if no "log" method has been defined
    return (
      this._implementation.log?.(...args) ?? this._implementation.info(...args)
    );
  };
  debug: LoggerFunction = (...args) => this._implementation.debug(...args);
  info: LoggerFunction = (...args) => this._implementation.info(...args);
  warn: LoggerFunction = (...args) => this._implementation.warn(...args);
  error: LoggerFunction = (...args) => this._implementation.error(...args);
  trace: LoggerFunction = (...args) => this._implementation.trace?.(...args);

  /**
   * Configure the Logger implementation
   * @param options - a configuration object that provides the Logger implementation to use. Defaults to "no-op" operations.
   */
  constructor(options?: {
    logger?: Logger;
  }) {
    if (options?.logger) {
      // replace our stubs with the actual logger
      this._implementation = options.logger;
      this._implementation.log.bind(options.logger);
      this._implementation.debug.bind(options.logger);
      this._implementation.info.bind(options.logger);
      this._implementation.warn.bind(options.logger);
      this._implementation.error.bind(options.logger);
      this._implementation.trace?.bind(options.logger);
    }
  }
}
