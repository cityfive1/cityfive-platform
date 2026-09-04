
/**
 * Verify a Fireblocks webhook signature.
 *
 * The raw HTTP request body must be supplied exactly as received.
 */
async function verifyWebhook(rawBody, signature) {
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


/**
 * Convert Fireblocks events into a small internal format.
 */
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


module.exports = {
  btcProviderReady,
  createBtcDepositAddress,
  submitBtcWithdrawal,
  processBtcWebhook,
  verifyWebhook,
  normalizeWebhookEvent
};
