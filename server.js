app.post(
  "/deposits/btc",
  requireAuth,
  async (req, res) => {
    try {
      if (!IS_SANDBOX) {
        return res.status(503).json({
          ok: false,
          error: "Live BTC deposits are disabled."
        });
      }

      const amount = Number(req.body.amount);

      if (
        !Number.isFinite(amount) ||
        amount <= 0 ||
        amount > 100
      ) {
        return res.status(400).json({
          ok: false,
          error: "Enter a valid BTC amount."
        });
      }

      const account = await Account.findOne({
        userId: req.user._id,
        currency: "BTC"
      });

      if (!account) {
        return res.status(404).json({
          ok: false,
          error: "BTC account not found."
        });
      }

      account.balance += amount;
      await account.save();

      const deposit = await Deposit.create({
        userId: req.user._id,
        asset: "BTC",
        amount,
        address: null,
        txid: null,
        status: "confirmed",
        mode: "SANDBOX"
      });

      await Ledger.create({
        userId: req.user._id,
        currency: "BTC",
        type: "deposit",
        amount,
        referenceId: String(deposit._id),
        description: "Simulated sandbox BTC deposit"
      });

      await audit({
        userId: req.user._id,
        actorId: req.user._id,
        action: "SANDBOX_BTC_DEPOSIT_CREATED",
        details: {
          depositId: String(deposit._id),
          amount
        },
        ip: req.ip
      });

      return res.json({
        ok: true,
        mode: "SANDBOX",
        realFundsEnabled: false,
        message: "Simulated BTC deposit added.",
        deposit
      });

    } catch (error) {
      console.error(
        "BTC deposit error:",
        error
      );

      return res.status(500).json({
        ok: false,
        error: "Unable to create BTC deposit."
      });
    }
  }
);
