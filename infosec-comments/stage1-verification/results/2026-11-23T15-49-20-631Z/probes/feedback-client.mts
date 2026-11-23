
import { createFeedbackTraceShareClientFromConfig } from "file:///Users/mac/repos/paperclip/server/src/services/feedback-share-client.ts";
const none = createFeedbackTraceShareClientFromConfig({ feedbackExportBackendUrl: undefined, feedbackExportBackendToken: undefined });
const blank = createFeedbackTraceShareClientFromConfig({ feedbackExportBackendUrl: "  ", feedbackExportBackendToken: undefined });
console.log(JSON.stringify({ none: none === undefined, blank: blank === undefined }));
