async function cityFiveAssistant(message, user, Account) {
  const q = String(message || "").trim().toLowerCase();

  if (!q) {
    return "Please type a question.";
  }

  // Balance
  if (
    q.includes("balance") ||
    q.includes("how much do i have") ||
    q.includes("how much is my")
  ) {
    try {
      const account = await Account.findOne({
        userId: user._id
      }).lean();

      if (!account) {
        return "Your CityFive sandbox account could not be found.";
      }

      return (
        "Your simulated CAD balance is $" +
        Number(account.cadBalance || 0).toFixed(2) +
        " and your simulated BTC balance is " +
        Number(account.btcBalance || 0).toFixed(7) +
        " BTC. These are sandbox values only and are not real funds."
      );
    } catch (error) {
      console.error("Sandbox balance error:", error);
      return "I could not retrieve your sandbox balance right now.";
    }
  }

  // Bitcoin
  if (
    q.includes("bitcoin") ||
    q.includes("what is btc") ||
    q.includes("what is bitcoin")
  ) {
    return (
      "Bitcoin is a decentralized digital asset that operates on a public blockchain. " +
      "CityFive currently uses simulated Bitcoin activity for demonstration purposes only."
    );
  }

  // Deposits
  if (
    q.includes("deposit") ||
    q.includes("add btc") ||
    q.includes("add bitcoin")
  ) {
    return (
      "CityFive sandbox deposits are simulated only. " +
      "They do not send real Bitcoin or interact with the Bitcoin blockchain."
    );
  }

  // Withdrawals
  if (
    q.includes("withdraw") ||
    q.includes("withdrawal")
  ) {
    return (
      "CityFive sandbox withdrawals are simulated only. " +
      "They do not send real Bitcoin and do not move real funds."
    );
  }

  // Transactions
  if (
    q.includes("transaction") ||
    q.includes("transactions") ||
    q.includes("history")
  ) {
    return (
      "You can review your simulated deposits, withdrawals and other activity " +
      "in the Transactions section of your CityFive sandbox dashboard."
    );
  }

  // KYC
  if (
    q.includes("kyc") ||
    q.includes("verification") ||
    q.includes("verify")
  ) {
    return (
      "KYC means Know Your Customer. In the CityFive sandbox, " +
      "verification is for demonstration purposes only."
    );
  }

  // Sandbox
  if (
    q.includes("sandbox") ||
    q.includes("real money") ||
    q.includes("real funds")
  ) {
    return (
      "CityFive is currently running in SANDBOX mode. " +
      "Balances, deposits, withdrawals and transactions are simulated " +
      "and do not represent real money or real Bitcoin."
    );
  }

  // Help
  if (
    q.includes("help") ||
    q.includes("what can you do")
  ) {
    return (
      "I am the free CityFive Sandbox Assistant. " +
      "I can help explain your simulated balance, Bitcoin activity, " +
      "transactions, deposits, withdrawals, KYC and Bitcoin basics."
    );
  }

  return (
    "I am the free CityFive Sandbox Assistant. " +
    "Try asking: How much is my balance? " +
    "You can also ask about Bitcoin, deposits, withdrawals, transactions or KYC."
  );
}

module.exports = cityFiveAssistant;
