process.env.DPDP_MEGA_TOTAL_USERS ??= "1000000";
process.env.DPDP_MEGA_PURGE_REQUESTS = "90000";
process.env.DPDP_MEGA_DELETE_REQUESTS = "10000";
process.env.DPDP_MEGA_WORKERS ??= "32";
process.env.DPDP_MEGA_REQUEST_CONCURRENCY ??= "200";
process.env.DPDP_MEGA_JOB_TIMEOUT_MS ??= String(12 * 60 * 60 * 1000);

await import("./mega-e2e");

//Makes this file a module and allows `await import("./mega-e2e")`
export { }; 