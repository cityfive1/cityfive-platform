async function cityFiveAssistant(message, user, Account) {
  const q = String(message || "").trim().toLowerCase();

  if (!q) return "Please type a question.";

  if (q.includes("balance") || q.includes("how much do i have") || q.includes("how much is my")) {
    try {
      const account = await Account.findOne({ user: user._id }).lean();

      if (!account) return "Your CityFive sandbox account could not be found.";

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

  if (q.includes("bitcoin") || q.includes("btc") || q.includes("what is bitcoin")) {
    return "Bitcoin (BTC) is a decentralized digital asset that operates on a public blockchain. CityFive currently uses simulated Bitcoin activity for demonstration purposes only.";
  }

  if (q.includes("deposit") || q.includes("add btc") || q.includes("add bitcoin") || q.includes("fund account")) {
    return "CityFive sandbox deposits are simulated only. They do not send real Bitcoin or interact with the Bitcoin blockchain.";
  }

  if (q.includes("withdraw") || q.includes("withdrawal") || q.includes("cash out")) {
    return "CityFive sandbox withdrawals are simulated only. They do not send real Bitcoin and do not move real funds.";
  }

  if (q.includes("transaction") || q.includes("transactions") || q.includes("history") || q.includes("activity")) {
    return "You can review your simulated account activity in the Transactions section of your CityFive sandbox dashboard.";
  }

  if (q.includes("kyc") || q.includes("verification") || q.includes("verify") || q.includes("identity")) {
    return "KYC means Know Your Customer. It is a process used by financial services to verify a customer's identity. In the CityFive sandbox, verification features are for demonstration purposes only.";
  }

  if (q.includes("security") || q.includes("secure") || q.includes("password") || q.includes("hack")) {
    return "For account security, use a strong unique password and never share your password or authentication codes. CityFive is currently operating in sandbox mode.";
  }

  if (q.includes("sandbox") || q.includes("real money") || q.includes("real funds") || q.includes("is this real") || q.includes("are my funds real")) {
    return "CityFive is currently running in SANDBOX mode. Balances, deposits, withdrawals and transactions are simulated and do not represent real money or real Bitcoin.";
  }

  if (q.includes("dashboard") || q.includes("where do i") || q.includes("how do i")) {
    return "You can use your CityFive dashboard to review your simulated balances, transactions, profile and other sandbox features.";
  }

  if (q.includes("help") || q.includes("what can you do") || q.includes("what do you do")) {
    return "I am the free CityFive Sandbox Assistant. I can help explain your simulated balance, Bitcoin activity, transactions, deposits, withdrawals, KYC, security and dashboard features.";
  }

  return "I am the free CityFive Sandbox Assistant. Try asking about your balance, Bitcoin, deposits, withdrawals, transactions, KYC, security or sandbox mode.";
}

module.exports = cityFiveAssistant;
