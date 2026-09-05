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

    const parts = signature.split(".");

    if (parts.length !== 3) {
      console.error(
        "Invalid Fireblocks detached JWS format"
      );
      return false;
    }

    const header = parts[0];
    const sig = parts[2];

    const payload =
      body.toString("base64url");

    const fullJws =
      `${header}.${payload}.${sig}`;

    await compactVerify(
      fullJws,
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
