import { existsSync, readFileSync } from "node:fs";
import { join as pathJoin } from "node:path";
import type { AmazonProxyOptions, Logger } from "../../types/types";

const FORMERDATA_STORE_VERSION = 4;

export function loadResult(config: AmazonProxyOptions) {
  const formerDataStorePath =
    config.formerDataStorePath ||
    pathJoin(__dirname, "../../data", "formerDataStore.json");

    if (existsSync(formerDataStorePath)) {
      const formerDataStore = JSON.parse(
        readFileSync(formerDataStorePath, "utf8"),
      );
      if (
        typeof formerDataStore === "object" &&
        formerDataStore.storeVersion === FORMERDATA_STORE_VERSION
      ) {
        return formerDataStore;
      }
    } else {
      throw new Error(`Former data store file not found at path: ${formerDataStorePath}`);
    }
}
