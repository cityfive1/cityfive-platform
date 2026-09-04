// ===============================
// REAL BTC PROVIDER INTEGRATION
// ===============================

const BTC_PROVIDER = process.env.BTC_PROVIDER || "none";
const BTC_PROVIDER_ENABLED =
  process.env.BTC_PROVIDER_ENABLED === "true";

const BTC_REQUIRED_CONFIRMATIONS =
  Number(process.env.BTC_REQUIRED_CONFIRMATIONS || 3);

const FIREBLOCKS_API_KEY =
  process.env.FIREBLOCKS_API_KEY || "";

const FIREBLOCKS_SECRET_KEY =
  process.env.FIREBLOCKS_SECRET_KEY || "";

const FIREBLOCKS_BASE_URL =
  process.env.FIREBLOCKS_BASE_URL || "";

const FIREBLOCKS_VAULT_ID =
  process.env.FIREBLOCKS_VAULT_ID || "";


/**
 * Provider status.
 *
 * This is intentionally separate from REAL_FUNDS_ENABLED.
 * Both controls must eventually be enabled before live movement.
 */
function btcProviderReady() {
  return (
    BTC_PROVIDER === "fireblocks" &&
    BTC_PROVIDER_ENABLED === true &&
    FIREBLOCKS_API_KEY &&
    FIREBLOCKS_SECRET_KEY &&
    FIREBLOCKS_BASE_URL &&
    FIREBLOCKS_VAULT_ID
  );
}


/**
 * Generate a BTC deposit address.
 *
 * IMPORTANT:
 * Do not generate private keys inside CityFive.
 * The custody provider owns/manages wallet infrastructure.
 */
async function createBtcDepositAddress({ userId }) {
  if (!btcProviderReady()) {
    return {
      mode: "SANDBOX",
      status: "provider_disabled",
      address: null,
      message:
        "Real BTC provider is not enabled. No blockchain address was created."
    };
  }

  /*
   * Provider-specific implementation goes here.
   *
   * The production implementation should:
   *
   * 1. Find/create the customer's provider wallet.
   * 2. Request a BTC deposit address.
   * 3. Save only the public address and provider IDs.
   * 4. NEVER save a private key.
   */

  throw new Error(
    "Live BTC provider adapter is not configured."
  );
}


/**
 * Submit an approved BTC withdrawal.
 *
 * This function NEVER signs a Bitcoin transaction itself.
 * The custody provider handles signing/authorization.
 */
async function submitBtcWithdrawal({
  userId,
  amount,
  address,
  reference
}) {
  if (!btcProviderReady()) {
    return {
      mode: "SANDBOX",
      status: "provider_disabled",
      txid: null,
      message:
        "Real BTC withdrawals are disabled."
    };
  }

  /*
   * Production provider call goes here.
   *
   * Expected sequence:
   *
   * CityFive approval
   *       ↓
   * provider transaction request
   *       ↓
   * provider policy/approval
   *       ↓
   * blockchain broadcast
   *       ↓
   * webhook
   *       ↓
   * CityFive records TXID
   */

  throw new Error(
    "Live BTC provider adapter is not configured."
  );
}


/**
 * Process a blockchain/provider webhook.
 *
 * The real implementation must verify the provider's
 * webhook signature before accepting the event.
 */
async function processBtcWebhook(event) {
  /*
   * 1. Verify webhook authenticity.
   * 2. Extract provider transaction ID.
   * 3. Check whether transaction already exists.
   * 4. Store/update BlockchainTransaction.
   * 5. Update confirmations.
   * 6. Credit the user's ledger only once.
   * 7. Write an AuditLog entry.
   */

  return {
    received: true,
    processed: false,
    message:
      "BTC webhook adapter awaiting provider configuration."
  };
}
