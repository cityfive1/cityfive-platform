
"use strict";

/**
 * CityFive Holdings Ltd
 * Fireblocks integration — SANDBOX ONLY
 *
 * IMPORTANT:
 * - This module does NOT connect to Fireblocks.
 * - No real wallets, assets, transfers, or withdrawals are handled.
 * - Real-funds functionality must remain disabled.
 */

const PLATFORM_MODE =
  process.env.PLATFORM_MODE || "SANDBOX";

const REAL_FUNDS_ENABLED =
  String(process.env.REAL_FUNDS_ENABLED || "false")
    .toLowerCase() === "true";

/**
 * Verify Fireblocks webhook.
 *
 * In SANDBOX mode this intentionally does not perform
 * real Fireblocks signature verification.
 *
 * Returns false rather than pretending a webhook is valid.
 */
async function verifyWebhook(rawBody, signature) {
  if (PLATFORM_MODE !== "SANDBOX" || REAL_FUNDS_ENABLED) {
    throw new Error(
      "Fireblocks integration is disabled until a separately reviewed production implementation is enabled."
    );
  }

  // Sandbox: never trust or process a real Fireblocks webhook.
  return false;
}

/**
 * Sandbox status helper.
 */
function getFireblocksStatus() {
  return {
    enabled: false,
    mode: "SANDBOX",
    realFundsEnabled: false,
    message:
      "Fireblocks integration is disabled. No real funds or blockchain transfers are processed."
  };
}

module.exports = {
  verifyWebhook,
  getFireblocksStatus
};
