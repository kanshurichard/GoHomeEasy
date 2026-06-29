import { createCloudflareWorker } from "./src/platform/cloudflare-worker.js";

export default createCloudflareWorker({
  defaultSubscriptionFormat: "ss",
});
