import { existsSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { AmazonProxyOptions } from "../../types/types";

/**
 * Save the result to the data store file
 * @param result - the result to store
 * @param config - the AmazonProxyOptions config
 */
export const saveResult = (result: object, config: AmazonProxyOptions) => {
  if (typeof result !== "object") {
    return;
  }
  const dataStoreFilename =
    config.formerDataStorePath ??
    path.join(__dirname, "../../data/formerDataStore.json");
  let formerDataStore = {};
  if (dataStoreFilename && existsSync(dataStoreFilename)) {
    formerDataStore = JSON.parse(readFileSync(dataStoreFilename, "utf8"));
  }
  writeFileSync(
    dataStoreFilename,
    JSON.stringify({ ...formerDataStore, ...result }),
    {
      encoding: "utf8",
    },
  );
};
