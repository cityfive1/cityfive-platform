
app.post(
  "/webhooks/fireblocks",
  express.raw({
    type: "application/json",
    limit: "2mb"
  }),
  async (req, res) => {
    try {
      const signature =
        req.headers["fireblocks-webhook-signature"];

      const valid = await verifyWebhook(
        req.body,
        signature
      );

      if (!valid) {
        console.warn(
          "Rejected Fireblocks webhook: invalid signature"
        );

        return res.status(401).json({
          error: "Invalid webhook signature"
        });
      }

      const event = JSON.parse(
        Buffer.from(req.body).toString("utf8")
      );

      const normalized =
        normalizeWebhookEvent(event);

      console.log(
        "Fireblocks webhook received:",
        normalized.eventType,
        normalized.txId,
        normalized.status
      );

      return res.json({
        received: true
      });
    } catch (error) {
      console.error(
        "Fireblocks webhook error:",
        error.message
      );

      return res.status(400).json({
        error: "Invalid webhook"
      });
    }
  }
);
