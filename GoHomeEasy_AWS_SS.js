import { createAwsHandler } from "./src/platform/aws-handler.js";

export const handler = createAwsHandler({
  defaultSubscriptionFormat: "ss",
});
