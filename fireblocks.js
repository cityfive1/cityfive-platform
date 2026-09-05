"use strict";

const { createRemoteJWKSet, compactVerify } = require("jose");

// =====================================
// FIREBLOCKS WEBHOOK VERIFICATION
// =====================================

const FIREBLOCKS_JWKS_URL =
  process.env.FIREBLOCKS_JWKS_URL ||
  "https://sandbox-keys.fireblocks.io/.well-known/jwks.json";

const FIREBLOCKS_JWKS = createRemoteJWKSet(
  new URL(FIREBLOCKS_JWKS_URL)
);


// =====================================
// BTC PROVIDER CONFIGURATION
// =====================================

const BTC_PROVIDER =
  process.env.BTC_PROVIDER || "none";

const BTC_PROVIDER_ENABLED =
  process.env.BTC_PROVIDER_ENABLED === "true";

const BTC_REQUIRED_CONFIRMATIONS =
  Number(
    process.env.BTC_REQUIRED_CONFIRMATIONS || 3
  );

const FIREBLOCKS_API_KEY =
  process.env.FIREBLOCKS_API_KEY || "";

const FIREBLOCKS_SECRET_KEY =
  process.env.FIREBLOCKS_SECRET_KEY || "";

const FIREBLOCKS_BASE_URL =
  process.env.FIREBLOCKS_BASE_URL || "";

const FIREBLOCKS_VAULT_ID =
  process.env.FIREBLOCKS_VAULT_ID || "";


// =====================================
// PROVIDER STATUS
// =====================================

function btcProviderReady() {
  return (
    BTC_PROVIDER === "fireblocks" &&
    BTC_PROVIDER_ENABLED === true &&
    !!FIREBLOCKS_API_KEY &&
    !!FIREBLOCKS_SECRET_KEY &&
    !!FIREBLOCKS_BASE_URL &&
    !!FIREBLOCKS_VAULT_ID
  );
}


// =====================================
// BTC DEPOSIT ADDRESS
// =====================================

async function createBtcDepositAddress({
  userId
}) {
  if (!btcProviderReady()) {
    return {
      mode: "SANDBOX",
      status: "provider_disabled",
      address: null,
      message:
        "Real BTC provider is not enabled."
    };
  }

  throw new Error(
    "Live BTC provider adapter is not configured."
  );
}


// =====================================
// BTC WITHDRAWAL
// =====================================

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

  throw new Error(
    "Live BTC provider adapter is not configured."
  );
}


// =====================================
// FIREBLOCKS WEBHOOK SIGNATURE
// =====================================

async function verifyWebhook(
  rawBody,
  signature
) {
  if (!signature) {
    return false;
  }

  if (!rawBody) {
    return false;
  }

  try {
    const body = Buffer.isBuffer(rawBody)
      ? rawBody
      : Buffer.from(rawBody);

    await compactVerify(
      signature,
      body,
      FIREBLOCKS_JWKS
    );

    return true;
  } catch (error) {
    console.error(
      "Fireblocks webhook verification failed:",
      error.message
    );

    return false;
  }
}


// =====================================
// NORMALIZE FIREBLOCKS EVENT
// =====================================

function normalizeWebhookEvent(event) {
  return {
    eventType:
      event?.type ||
      event?.eventType ||
      null,

    txId:
      event?.data?.id ||
      event?.data?.txId ||
      event?.id ||
      null,

    status:
      event?.data?.status ||
      event?.status ||
      null,

    assetId:
      event?.data?.assetId ||
      event?.assetId ||
      null,

    amount:
      event?.data?.amount ||
      event?.amount ||
      null
  };
}


// =====================================
// PROCESS BTC WEBHOOK
// =====================================

async function processBtcWebhook(event) {
  return {
    received: true,
    processed: false,
    message:
      "Webhook verified. Blockchain processing is not enabled yet."
  };
}


// =====================================
// EXPORTS
// =====================================

module.exports = {
  btcProviderReady,
  createBtcDepositAddress,
  submitBtcWithdrawal,
  processBtcWebhook,
  verifyWebhook,
  normalizeWebhookEvent
};
