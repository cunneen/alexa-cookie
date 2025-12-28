/** biome-ignore-all lint/suspicious/noExplicitAny: pino uses 'any' */
import path from "node:path";
import pino, {
  type LevelWithSilentOrString,
  type TransportPipelineOptions,
  type TransportTargetOptions,
} from "pino";
import pretty, { type PrettyOptions } from "pino-pretty";
import type { Logger } from "../../types/types";

/** Type Definition Config for the logger.  */
export type LoggerOptions = {
  /** The overriding logging level for all logger transports. Defaults to `'info'` */
  level: LevelWithSilentOrString | undefined;
  /** whether to output to a log file. Defaults to `true`. Specify `false` to suppress. */
  outputLogFileEnabled?: boolean;
  /** the path to the output log file, as a string. Folders in the path will be created if they do not already exist. Defaults to '<project root>/logs/example.log.jsonl'. */
  outputLogFilePath?: string;
  /** the logging level for the output file, defaults to `'info'` */
  outputLogFileLevel: LevelWithSilentOrString | undefined;
  /** whether to output to the console (actually STDOUT). Defaults to `true`. Specify `false` to suppress, or `'TTY'` to enable only when `process.stdout.isTTY === true` */
  outputConsoleEnabled?: boolean | "TTY";
  /** whether to pretty-print the console logs. Defaults to `true`. Specify `false` to suppress. */
  outputConsolePretty?: boolean;
  /** whether to colorize the console logs. Defaults to `true`. Specify `false` to suppress. Only works if `outputConsoleEnabled` is not false and `outputConsolePretty` */
  outputConsoleColorize?: boolean;
  /** the logging level for the console logs, defaults to `'info'` */
  outputConsoleLevel: LevelWithSilentOrString | undefined;
  /** any other config options for the pino logger. These will get passed to pino as a rest spread property, and can potentially override other properties */
  pinoOptions?: pino.LoggerOptions;
};

/** Item type for pino transport config. Copied from pino. */
type PinoTransportItemType = TransportTargetOptions<Record<string, any>>;
type PinoTransportPipelineItemType = TransportPipelineOptions<
  Record<string, any>
>;

// ==== CONFIG ====
// defaults, as specified in the tsdoc comments for LoggerOptions
const DEFAULT_LOG_LEVEL =
  process.env.PINO_LOG_LEVEL || process.env.LOG_LEVEL || "debug";
const defaultLoggerOptions: LoggerOptions = {
  level: DEFAULT_LOG_LEVEL,
  outputLogFileEnabled: true,
  outputLogFilePath: path.join(__dirname, "../../logs/example.log.jsonl"),
  outputLogFileLevel: DEFAULT_LOG_LEVEL,
  outputConsoleEnabled: true,
  outputConsolePretty: true,
  outputConsoleLevel: DEFAULT_LOG_LEVEL,
};

// === custom pino transport ===

/**
 * Gets a Logger instance
 * @param options an object containing custom configuration for the logger
 */
export function getLogger(
  options: LoggerOptions = defaultLoggerOptions,
): Logger {
  // dynamically import our inline JS module

  // ensure option defaults are set
  options = { ...defaultLoggerOptions, ...options };
  // (empty) transports array
  const pinoTransportTargets = [] as (
    | PinoTransportItemType
    | PinoTransportPipelineItemType
  )[];
  const pinoTemplate = {
    target: "pino-template",
    options: {
      template: `<% 
        const {context, data} = it; 
      %><%= 
        JSON.stringify({...data, "level":context?.[data.level] ?? data.level}) 
      %>`,
      templateContext: pino.levels.labels,
    },
    level: "debug",
  };
  // pretty-print to console/STDOUT if desired
  if (
    options.outputConsoleEnabled === true ||
    (options.outputConsoleEnabled === "TTY" && process.stdout.isTTY)
  ) {
    const consoleOptions: PinoTransportItemType = {
      target: "pino/file",
      level: options.outputConsoleLevel,
    } as PinoTransportItemType;
    if (options.outputConsolePretty === true) {
      consoleOptions.target = "pino-pretty";
      const prettyOptions: PrettyOptions = {};
      if (options.outputConsoleColorize === true && pretty.isColorSupported) {
        prettyOptions.colorize = true;
      }
      consoleOptions.options = prettyOptions;
    }
    pinoTransportTargets.push(consoleOptions);
  }

  // log to file if desired
  if (options.outputLogFileEnabled === true) {
    const fileOptions: PinoTransportItemType = {
      target: "pino/file",
      level: options.outputLogFileLevel,
      options: {
        destination: options.outputLogFilePath,
        append: false,
        mkdir: true,
      },
    } as PinoTransportItemType;
    pinoTransportTargets.push({
      pipeline: [pinoTemplate, fileOptions],
      level: options.outputLogFileLevel ?? DEFAULT_LOG_LEVEL,
    });
  }

  const pinoOptions = {
    level: options.level, // this just *enables* the logging level output in the pino logger, we *also* need to set the AmazonProxyOptions.proxyLogLevel
    customLevels: {
      log: 31, // defines 'logger.log()' as equivalent to 'logger.info()'
    },

    // // // === this seems to cause a problem : it gets stringified to "formatters": {}
    // formatters: {
    //   level: (label) => {
    //     return { level: label.toUpperCase() };
    //   },
    // },
  } as pino.LoggerOptions;

  const pinoTransportConfig = {
    targets: pinoTransportTargets,
    levels: pinoOptions.customLevels ?? {},
  };

  const transport = pino.transport(pinoTransportConfig);
  const logger: Logger = pino(pinoOptions, transport) as unknown as Logger;
  logger.log.bind(logger.info); // ensure "logger.log()" shares the same context variables as "logger.info()"
  // console.log(JSON.stringify(pinoOptions, null, 2), JSON.stringify(pinoTransportConfig, null, 2))
  return logger;
}
