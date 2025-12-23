import alexaCookie from "../alexa-cookie";

import { config } from "./config";

// You can explicitly set `config.formerRegistratinData` here, otherwise it will use the file in the configured location (i.e. `config.formerDataStorePath`, which defaults to "<project dir>/data/formerDataStore.json")
// config.formerRegistrationData = {
//   /* ... */
// } // required: provide the result object from previous proxy usages here and some generated data will be reused for next proxy call too

alexaCookie.refreshAlexaCookie(config, (err, result) => {
  console.log(`RESULT: ${err} / ${JSON.stringify(result)}`);
});
