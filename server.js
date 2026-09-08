const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const OpenAI = require("openai");

const app = express();

const PORT = Number(process.env.PORT || 3000);

const MONGO_URI = process.env.MONGO_URI;
const FRONTEND_ORIGIN =
process.env.FRONTEND_ORIGIN ||
"https://cityfive1.github.io";

const SESSION_SECRET =
process.env.SESSION_SECRET;

const PLATFORM_MODE =
process.env.PLATFORM_MODE || "SANDBOX";

const REAL_FUNDS_ENABLED =
String(process.env.REAL_FUNDS_ENABLED).toLowerCase() === "true";

const SANDBOX_RESET_KEY =
process.env.SANDBOX_RESET_KEY;

const OPENAI_API_KEY =
process.env.OPENAI_API_KEY;

const OPENAI_MODEL =
process.env.OPENAI_MODEL || "gpt-5.5";

if (!MONGO_URI) {
throw new Error("MONGO_URI is required");
}

if (!SESSION_SECRET) {
throw new Error("SESSION_SECRET is required");
}

if (PLATFORM_MODE !== "SANDBOX") {
throw new Error(
"This CityFive version is SANDBOX-only."
);
}

if (REAL_FUNDS_ENABLED) {
throw new Error(
"REAL_FUNDS_ENABLED must remain false."
);
}

app.use(
cors({
origin: [
FRONTEND_ORIGIN,
"https://cityfive1.github.io",
"http://localhost:3000",
"http://127.0.0.1:3000"
]
})
);

app.use(
express.json({
limit: "1mb"
})
);

function sha256(value) {
return crypto
.createHash("sha256")
.update(String(value))
.digest("hex");
}

function randomToken(bytes = 32) {
return crypto
.randomBytes(bytes)
.toString("hex");
}

function publicUser(user) {
return {
id: String(user._id),
name: user.name,
email: user.email,
role: user.role,
createdAt: user.createdAt
};
}

/* =========================
MODELS
========================= */

const userSchema =
new mongoose.Schema(
{
name: {
type: String,
required: true,
trim: true
},

  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },

  passwordHash: {
    type: String,
    required: true
  },

  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user"
  }
},
{
  timestamps: true
}

);

const User =
mongoose.model("User", userSchema);

const authTokenSchema =
new mongoose.Schema(
{
tokenHash: {
type: String,
required: true,
unique: true
},

  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },

  expiresAt: {
    type: Date,
    required: true
  }
},
{
  timestamps: true
}

);

const AuthToken =
mongoose.model(
"AuthToken",
authTokenSchema
);

const passwordResetSchema =
new mongoose.Schema(
{
userId: {
type: mongoose.Schema.Types.ObjectId,
ref: "User",
required: true
},

  tokenHash: {
    type: String,
    required: true
  },

  expiresAt: {
    type: Date,
    required: true
  }
},
{
  timestamps: true
}

);

const PasswordReset =
mongoose.model(
"PasswordReset",
passwordResetSchema
);

/*

* IMPORTANT:
* CAD and BTC are now completely separate.
  */

const accountSchema =
new mongoose.Schema(
{
userId: {
type: mongoose.Schema.Types.ObjectId,
ref: "User",
unique: true,
required: true
},

  cadBalance: {
    type: Number,
    default: 0
  },

  btcBalance: {
    type: Number,
    default: 0
  },

  pendingBtcBalance: {
    type: Number,
    default: 0
  }
},
{
  timestamps: true
}

);

const Account =
mongoose.model(
"Account",
accountSchema
);

const depositSchema =
new mongoose.Schema(
{
userId: {
type: mongoose.Schema.Types.ObjectId,
ref: "User",
required: true
},

  currency: {
    type: String,
    default: "BTC"
  },

  amount: {
    type: Number,
    required: true
  },

  status: {
    type: String,
    enum: [
      "pending",
      "confirmed",
      "cancelled"
    ],
    default: "pending"
  },

  address: {
    type: String,
    default: null
  },

  txid: {
    type: String,
    default: null
  },

  confirmedAt: {
    type: Date,
    default: null
  }
},
{
  timestamps: true
}

);

const Deposit =
mongoose.model(
"Deposit",
depositSchema
);

const withdrawalSchema =
new mongoose.Schema(
{
userId: {
type: mongoose.Schema.Types.ObjectId,
ref: "User",
required: true
},

  currency: {
    type: String,
    default: "BTC"
  },

  amount: {
    type: Number,
    required: true
  },

  address: {
    type: String,
    required: true
  },

  status: {
    type: String,
    enum: [
      "pending",
      "approved",
      "rejected",
      "completed"
    ],
    default: "pending"
  },

  txid: {
    type: String,
    default: null
  },

  reviewedAt: {
    type: Date,
    default: null
  }
},
{
  timestamps: true
}

);

const Withdrawal =
mongoose.model(
"Withdrawal",
withdrawalSchema
);

const ledgerSchema =
new mongoose.Schema(
{
userId: {
type: mongoose.Schema.Types.ObjectId,
ref: "User",
required: true
},

  type: {
    type: String,
    required: true
  },

  currency: {
    type: String,
    required: true
  },

  amount: {
    type: Number,
    required: true
  },

  description: {
    type: String,
    default: ""
  },

  referenceId: {
    type: String,
    default: null
  }
},
{
  timestamps: true
}

);

const Ledger =
mongoose.model(
"Ledger",
ledgerSchema
);

const kycSchema =
new mongoose.Schema(
{
userId: {
type: mongoose.Schema.Types.ObjectId,
ref: "User",
unique: true,
required: true
},

  status: {
    type: String,
    enum: [
      "not_started",
      "pending",
      "approved",
      "rejected"
    ],
    default: "not_started"
  },

  fullName: {
    type: String,
    default: ""
  },

  country: {
    type: String,
    default: ""
  },

  documentType: {
    type: String,
    default: ""
  }
},
{
  timestamps: true
}

);

const KycProfile =
mongoose.model(
"KycProfile",
kycSchema
);

const auditSchema =
new mongoose.Schema(
{
action: {
type: String,
required: true
},

  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    default: null
  },

  metadata: {
    type: mongoose.Schema.Types.Mixed,
    default: {}
  }
},
{
  timestamps: true
}

);

const Audit =
mongoose.model(
"Audit",
auditSchema
);

/* =========================
HELPERS
========================= */

async function audit(
action,
userId = null,
metadata = {}
) {
try {
await Audit.create({
action,
userId,
metadata
});
} catch (error) {
console.error(
"Audit error:",
error.message
);
}
}

async function issueToken(user) {
const rawToken =
randomToken(32);

await AuthToken.create({
tokenHash:
sha256(rawToken),

userId:
  user._id,

expiresAt:
  new Date(
    Date.now() +
      1000 *
      60 *
      60 *
      24 *
      30
  )

});

return rawToken;
}

function bearer(req) {
const header =
req.headers.authorization || "";

if (
!header.startsWith(
"Bearer "
)
) {
return null;
}

return header
.slice(7)
.trim();
}

async function requireAuth(
req,
res,
next
) {
try {
const token =
bearer(req);

if (!token) {
  return res.status(401).json({
    error:
      "Authentication required"
  });
}

const authToken =
  await AuthToken.findOne({
    tokenHash:
      sha256(token)
  });

if (!authToken) {
  return res.status(401).json({
    error:
      "Invalid session"
  });
}

if (
  authToken.expiresAt <
  new Date()
) {
  await AuthToken.deleteOne({
    _id:
      authToken._id
  });

  return res.status(401).json({
    error:
      "Session expired"
  });
}

const user =
  await User.findById(
    authToken.userId
  );

if (!user) {
  return res.status(401).json({
    error:
      "User not found"
  });
}

req.user = user;
req.authToken =
  authToken;

next();

} catch (error) {
console.error(
"Auth error:",
error
);

return res.status(500).json({
  error:
    "Authentication failed"
});

}
}

async function requireAdmin(
req,
res,
next
) {
await requireAuth(
req,
res,
() => {
if (
req.user.role !==
"admin"
) {
return res.status(403).json({
error:
"Admin access required"
});
}

  next();
}

);
}

async function ensureAccounts(
userId
) {
let account =
await Account.findOne({
userId
});

if (!account) {
account =
await Account.create({
userId,
cadBalance: 0,
btcBalance: 0,
pendingBtcBalance: 0
});
}

/*

* Migration protection:
* Older accounts may have the old
* availableBalance field.
  */

if (
typeof account.cadBalance !==
"number"
) {
account.cadBalance = 0;
}

if (
typeof account.btcBalance !==
"number"
) {
account.btcBalance = 0;
}

if (
typeof account.pendingBtcBalance !==
"number"
) {
account.pendingBtcBalance = 0;
}

return account;
}

function validBtcAmount(
value
) {
const amount =
Number(value);

if (
!Number.isFinite(amount) ||
amount <= 0 ||
amount > 100
) {
return null;
}

return amount;
}

/* =========================
PUBLIC
========================= */

app.get(
"/",
(req, res) => {
res.json({
service:
"CityFive Holdings Ltd",
status: "online",
mode: "SANDBOX",
realFundsEnabled: false
});
}
);

app.get(
"/health",
(req, res) => {
res.json({
status: "ok",
service:
"CityFive Holdings Ltd",
mode: "SANDBOX",
realFundsEnabled: false
});
}
);

/* =========================
REGISTER
========================= */

app.post(
"/register",
async (req, res) => {
try {
const {
name,
email,
password
} = req.body;

  if (
    !name ||
    !email ||
    !password
  ) {
    return res.status(400).json({
      error:
        "Name, email and password are required"
    });
  }

  if (
    String(password).length < 8
  ) {
    return res.status(400).json({
      error:
        "Password must be at least 8 characters"
    });
  }

  const normalizedEmail =
    String(email)
      .trim()
      .toLowerCase();

  const existing =
    await User.findOne({
      email:
        normalizedEmail
    });

  if (existing) {
    return res.status(409).json({
      error:
        "An account with that email already exists"
    });
  }

  const passwordHash =
    await bcrypt.hash(
      String(password),
      12
    );

  const user =
    await User.create({
      name:
        String(name).trim(),
      email:
        normalizedEmail,
      passwordHash,
      role: "user"
    });

  await Account.create({
    userId:
      user._id,
    cadBalance: 0,
    btcBalance: 0,
    pendingBtcBalance: 0
  });

  await KycProfile.create({
    userId:
      user._id
  });

  const token =
    await issueToken(user);

  await audit(
    "USER_REGISTERED",
    user._id
  );

  return res.status(201).json({
    user:
      publicUser(user),
    token
  });
} catch (error) {
  console.error(
    "Register error:",
    error
  );

  return res.status(500).json({
    error:
      "Registration failed"
  });
}

}
);

/* =========================
LOGIN
========================= */

app.post(
"/login",
async (req, res) => {
try {
const {
email,
password
} = req.body;

  if (
    !email ||
    !password
  ) {
    return res.status(400).json({
      error:
        "Email and password are required"
    });
  }

  const normalizedEmail =
    String(email)
      .trim()
      .toLowerCase();

  const user =
    await User.findOne({
      email:
        normalizedEmail
    });

  if (!user) {
    return res.status(401).json({
      error:
        "Invalid email or password"
    });
  }

  const valid =
    await bcrypt.compare(
      String(password),
      user.passwordHash
    );

  if (!valid) {
    return res.status(401).json({
      error:
        "Invalid email or password"
    });
  }

  await ensureAccounts(
    user._id
  );

  const token =
    await issueToken(user);

  await audit(
    "USER_LOGIN",
    user._id
  );

  return res.json({
    user:
      publicUser(user),
    token
  });
} catch (error) {
  console.error(
    "Login error:",
    error
  );

  return res.status(500).json({
    error:
      "Login failed"
  });
}

}
);

/* =========================
ME
========================= */

app.get(
"/me",
requireAuth,
(req, res) => {
res.json({
user:
publicUser(req.user)
});
}
);

/* =========================
ACCOUNT
========================= */

app.get(
"/accounts",
requireAuth,
async (req, res) => {
try {
const account =
await ensureAccounts(
req.user._id
);

  res.json({
    account: {
      cadBalance:
        Number(
          account.cadBalance || 0
        ),

      btcBalance:
        Number(
          account.btcBalance || 0
        ),

      pendingBtcBalance:
        Number(
          account.pendingBtcBalance || 0
        )
    }
  });
} catch (error) {
  console.error(
    "Account error:",
    error
  );

  res.status(500).json({
    error:
      "Could not load account"
  });
}

}
);

/* =========================
SANDBOX BTC DEPOSIT
========================= */

app.post(
"/deposits/btc",
requireAuth,
async (req, res) => {
try {
const amount =
validBtcAmount(
req.body.amount
);

  if (amount === null) {
    return res.status(400).json({
      error:
        "Enter a valid BTC amount between 0 and 100."
    });
  }

  const deposit =
    await Deposit.create({
      userId:
        req.user._id,

      currency:
        "BTC",

      amount,

      status:
        "pending",

      address:
        "SANDBOX-BTC-" +
        randomToken(8)
    });

  await audit(
    "SANDBOX_BTC_DEPOSIT_CREATED",
    req.user._id,
    {
      depositId:
        String(
          deposit._id
        ),
      amount
    }
  );

  res.status(201).json({
    message:
      "Simulated BTC deposit generated.",
    deposit
  });
} catch (error) {
  console.error(
    "Deposit error:",
    error
  );

  res.status(500).json({
    error:
      "Could not create deposit"
  });
}

}
);

/* =========================
CONFIRM SANDBOX DEPOSIT
========================= */

app.post(
"/deposits/btc/:id/confirm",
requireAuth,
async (req, res) => {
try {
const deposit =
await Deposit.findOne({
_id:
req.params.id,

      userId:
        req.user._id
    });

  if (!deposit) {
    return res.status(404).json({
      error:
        "Deposit not found"
    });
  }

  if (
    deposit.status ===
    "confirmed"
  ) {
    return res.json({
      message:
        "Deposit already confirmed.",
      deposit
    });
  }

  if (
    deposit.status !==
    "pending"
  ) {
    return res.status(400).json({
      error:
        "Deposit cannot be confirmed."
    });
  }

  /*
   * SANDBOX ONLY.
   *
   * This is the point where the
   * simulated BTC balance increases.
   */

  const account =
    await ensureAccounts(
      req.user._id
    );

  account.btcBalance +=
    deposit.amount;

  await account.save();

  deposit.status =
    "confirmed";

  deposit.confirmedAt =
    new Date();

  deposit.txid =
    "SANDBOX-TX-" +
    randomToken(12);

  await deposit.save();

  await Ledger.create({
    userId:
      req.user._id,

    type:
      "deposit",

    currency:
      "BTC",

    amount:
      deposit.amount,

    description:
      "Simulated BTC deposit confirmed",

    referenceId:
      String(
        deposit._id
      )
  });

  await audit(
    "SANDBOX_BTC_DEPOSIT_CONFIRMED",
    req.user._id,
    {
      depositId:
        String(
          deposit._id
        ),
      amount:
        deposit.amount
    }
  );

  res.json({
    message:
      "Simulated BTC deposit confirmed.",

    deposit,

    account: {
      cadBalance:
        Number(
          account.cadBalance || 0
        ),

      btcBalance:
        Number(
          account.btcBalance || 0
        ),

      pendingBtcBalance:
        Number(
          account.pendingBtcBalance || 0
        )
    }
  });
} catch (error) {
  console.error(
    "Deposit confirmation error:",
    error
  );

  res.status(500).json({
    error:
      "Could not confirm deposit"
  });
}

}
);

/* =========================
DEPOSITS
========================= */

app.get(
"/deposits",
requireAuth,
async (req, res) => {
try {
const deposits =
await Deposit.find({
userId:
req.user._id
}).sort({
createdAt: -1
});

  res.json({
    deposits
  });
} catch (error) {
  console.error(
    "Deposits error:",
    error
  );

  res.status(500).json({
    error:
      "Could not load deposits"
  });
}

}
);

/* =========================
SANDBOX WITHDRAWAL
========================= */

app.post(
"/withdrawals/btc",
requireAuth,
async (req, res) => {
try {
const amount =
validBtcAmount(
req.body.amount
);

  const address =
    String(
      req.body.address || ""
    ).trim();

  if (amount === null) {
    return res.status(400).json({
      error:
        "Enter a valid BTC amount."
    });
  }

  if (!address) {
    return res.status(400).json({
      error:
        "Destination is required."
    });
  }

  const account =
    await ensureAccounts(
      req.user._id
    );

  if (
    account.btcBalance <
    amount
  ) {
    return res.status(400).json({
      error:
        "Insufficient simulated BTC balance."
    });
  }

  account.btcBalance -=
    amount;

  account.pendingBtcBalance +=
    amount;

  await account.save();

  const withdrawal =
    await Withdrawal.create({
      userId:
        req.user._id,

      currency:
        "BTC",

      amount,

      address,

      status:
        "pending"
    });

  await Ledger.create({
    userId:
      req.user._id,

    type:
      "withdrawal_pending",

    currency:
      "BTC",

    amount:
      -amount,

    description:
      "Simulated BTC withdrawal requested",

    referenceId:
      String(
        withdrawal._id
      )
  });

  await audit(
    "SANDBOX_BTC_WITHDRAWAL_CREATED",
    req.user._id,
    {
      withdrawalId:
        String(
          withdrawal._id
        ),
      amount
    }
  );

  res.status(201).json({
    message:
      "Simulated withdrawal submitted for approval.",

    withdrawal,

    account
  });
} catch (error) {
  console.error(
    "Withdrawal error:",
    error
  );

  res.status(500).json({
    error:
      "Could not create withdrawal"
  });
}

}
);

/* =========================
WITHDRAWALS
========================= */

app.get(
"/withdrawals",
requireAuth,
async (req, res) => {
try {
const withdrawals =
await Withdrawal.find({
userId:
req.user._id
}).sort({
createdAt: -1
});

  res.json({
    withdrawals
  });
} catch (error) {
  console.error(
    "Withdrawals error:",
    error
  );

  res.status(500).json({
    error:
      "Could not load withdrawals"
  });
}

}
);

/* =========================
TRANSACTIONS
========================= */

app.get(
"/transactions",
requireAuth,
async (req, res) => {
try {
const transactions =
await Ledger.find({
userId:
req.user._id
}).sort({
createdAt: -1
});

  res.json({
    transactions
  });
} catch (error) {
  console.error(
    "Transactions error:",
    error
  );

  res.status(500).json({
    error:
      "Could not load transactions"
  });
}

}
);

/* =========================
KYC
========================= */

app.get(
"/kyc",
requireAuth,
async (req, res) => {
try {
const kyc =
await KycProfile.findOne({
userId:
req.user._id
});

  res.json({
    kyc:
      kyc || {
        status:
          "not_started"
      }
  });
} catch (error) {
  res.status(500).json({
    error:
      "Could not load KYC"
  });
}

}
);

app.post(
"/kyc/submit",
requireAuth,
async (req, res) => {
try {
const kyc =
await KycProfile.findOneAndUpdate(
{
userId:
req.user._id
},
{
$set: {
status:
"pending"
}
},
{
new: true,
upsert: true
}
);

  await audit(
    "KYC_SUBMITTED",
    req.user._id
  );

  res.json({
    message:
      "Verification request submitted.",
    kyc
  });
} catch (error) {
  res.status(500).json({
    error:
      "KYC submission failed"
  });
}

}
);

/* =========================
LOGOUT
========================= */

app.post(
"/logout",
requireAuth,
async (req, res) => {
try {
await AuthToken.deleteOne({
_id:
req.authToken._id
});

  await audit(
    "USER_LOGOUT",
    req.user._id
  );

  res.json({
    message:
      "Logged out successfully"
  });
} catch (error) {
  res.status(500).json({
    error:
      "Logout failed"
  });
}

}
);

/* =========================
ADMIN USERS
========================= */

app.get(
"/admin/users",
requireAdmin,
async (req, res) => {
try {
const users =
await User.find({})
.select(
"_id name email role createdAt"
)
.sort({
createdAt: -1
});

  res.json({
    users
  });
} catch (error) {
  res.status(500).json({
    error:
      "Could not load users"
  });
}

}
);

/* =========================
ADMIN WITHDRAWALS
========================= */

app.get(
"/admin/withdrawals",
requireAdmin,
async (req, res) => {
try {
const withdrawals =
await Withdrawal.find({})
.populate(
"userId",
"name email"
)
.sort({
createdAt: -1
});

  res.json({
    withdrawals
  });
} catch (error) {
  res.status(500).json({
    error:
      "Could not load withdrawals"
  });
}

}
);

/* =========================
ADMIN APPROVE
========================= */

app.post(
"/admin/withdrawals/:id/approve",
requireAdmin,
async (req, res) => {
try {
const withdrawal =
await Withdrawal.findById(
req.params.id
);

  if (!withdrawal) {
    return res.status(404).json({
      error:
        "Withdrawal not found"
    });
  }

  if (
    withdrawal.status !==
    "pending"
  ) {
    return res.status(400).json({
      error:
        "Withdrawal is not pending"
    });
  }

  const account =
    await ensureAccounts(
      withdrawal.userId
    );

  account.pendingBtcBalance -=
    withdrawal.amount;

  if (
    account.pendingBtcBalance <
    0
  ) {
    account.pendingBtcBalance =
      0;
  }

  withdrawal.status =
    "approved";

  withdrawal.reviewedAt =
    new Date();

  withdrawal.txid =
    "SANDBOX-WITHDRAWAL-" +
    randomToken(12);

  await account.save();
  await withdrawal.save();

  await audit(
    "SANDBOX_WITHDRAWAL_APPROVED",
    req.user._id,
    {
      withdrawalId:
        String(
          withdrawal._id
        )
    }
  );

  res.json({
    message:
      "Simulated withdrawal approved.",
    withdrawal,
    account
  });
} catch (error) {
  console.error(
    error
  );

  res.status(500).json({
    error:
      "Could not approve withdrawal"
  });
}

}
);

/* =========================
ADMIN REJECT
========================= */

app.post(
"/admin/withdrawals/:id/reject",
requireAdmin,
async (req, res) => {
try {
const withdrawal =
await Withdrawal.findById(
req.params.id
);

  if (!withdrawal) {
    return res.status(404).json({
      error:
        "Withdrawal not found"
    });
  }

  if (
    withdrawal.status !==
    "pending"
  ) {
    return res.status(400).json({
      error:
        "Withdrawal is not pending"
    });
  }

  const account =
    await ensureAccounts(
      withdrawal.userId
    );

  account.pendingBtcBalance -=
    withdrawal.amount;

  if (
    account.pendingBtcBalance <
    0
  ) {
    account.pendingBtcBalance =
      0;
  }

  account.btcBalance +=
    withdrawal.amount;

  withdrawal.status =
    "rejected";

  withdrawal.reviewedAt =
    new Date();

  await account.save();
  await withdrawal.save();

  await Ledger.create({
    userId:
      withdrawal.userId,

    type:
      "withdrawal_rejected",

    currency:
      "BTC",

    amount:
      withdrawal.amount,

    description:
      "Simulated BTC withdrawal rejected and balance returned",

    referenceId:
      String(
        withdrawal._id
      )
  });

  await audit(
    "SANDBOX_WITHDRAWAL_REJECTED",
    req.user._id,
    {
      withdrawalId:
        String(
          withdrawal._id
        )
    }
  );

  res.json({
    message:
      "Simulated withdrawal rejected.",
    withdrawal,
    account
  });
} catch (error) {
  console.error(
    error
  );

  res.status(500).json({
    error:
      "Could not reject withdrawal"
  });
}

}
);

/* =========================
SANDBOX PASSWORD RESET
========================= */

app.post(
"/sandbox/request-password-reset",
async (req, res) => {
try {
const {
email,
sandboxResetKey
} = req.body;

  if (
    !SANDBOX_RESET_KEY ||
    sandboxResetKey !==
      SANDBOX_RESET_KEY
  ) {
    return res.status(403).json({
      error:
        "Sandbox reset not authorized"
    });
  }

  const user =
    await User.findOne({
      email:
        String(email)
          .trim()
          .toLowerCase()
    });

  if (!user) {
    return res.status(404).json({
      error:
        "User not found"
    });
  }

  const token =
    randomToken(32);

  await PasswordReset.create({
    userId:
      user._id,

    tokenHash:
      sha256(token),

    expiresAt:
      new Date(
        Date.now() +
          1000 *
          60 *
          15
      )
  });

  res.json({
    message:
      "Sandbox reset token created.",
    token
  });
} catch (error) {
  res.status(500).json({
    error:
      "Password reset request failed"
  });
}

}
);

app.post(
"/sandbox/reset-password",
async (req, res) => {
try {
const {
token,
newPassword,
sandboxResetKey
} = req.body;

  if (
    !SANDBOX_RESET_KEY ||
    sandboxResetKey !==
      SANDBOX_RESET_KEY
  ) {
    return res.status(403).json({
      error:
        "Sandbox reset not authorized"
    });
  }

  if (
    !token ||
    !newPassword ||
    String(newPassword).length < 8
  ) {
    return res.status(400).json({
      error:
        "Valid token and password are required"
    });
  }

  const reset =
    await PasswordReset.findOne({
      tokenHash:
        sha256(token)
    });

  if (!reset) {
    return res.status(400).json({
      error:
        "Invalid reset token"
    });
  }

  if (
    reset.expiresAt <
    new Date()
  ) {
    return res.status(400).json({
      error:
        "Reset token expired"
    });
  }

  const passwordHash =
    await bcrypt.hash(
      String(newPassword),
      12
    );

  await User.updateOne(
    {
      _id:
        reset.userId
    },
    {
      $set: {
        passwordHash
      }
    }
  );

  await AuthToken.deleteMany({
    userId:
      reset.userId
  });

  await PasswordReset.deleteMany({
    userId:
      reset.userId
  });

  res.json({
    message:
      "Password reset successfully."
  });
} catch (error) {
  res.status(500).json({
    error:
      "Password reset failed"
  });
}

}
);

/* =========================
AI
========================= */

app.post(
"/ai/chat",
requireAuth,
async (req, res) => {
try {
if (!OPENAI_API_KEY) {
return res.status(503).json({
error:
"AI service is not configured"
});
}

  const message =
    String(
      req.body.message || ""
    ).trim();

  if (!message) {
    return res.status(400).json({
      error:
        "Message is required"
    });
  }

  const client =
    new OpenAI({
      apiKey:
        OPENAI_API_KEY
    });

  const response =
    await client.responses.create(
      {
        model:
          OPENAI_MODEL,

        instructions:
          "You are the CityFive Holdings Ltd sandbox assistant. Clearly explain that balances and transactions are simulated and that no real customer funds, Bitcoin transfers, or guaranteed investment returns are enabled.",

        input:
          message
      }
    );

  res.json({
    message:
      response.output_text ||
      "No response generated."
  });
} catch (error) {
  console.error(
    "AI error:",
    error
  );

  res.status(500).json({
    error:
      "AI request failed"
  });
}

}
);

/* =========================
ERROR HANDLER
========================= */

app.use(
(
error,
req,
res,
next
) => {
console.error(
"Unhandled error:",
error
);

if (res.headersSent) {
  return next(error);
}

res.status(500).json({
  error:
    "Internal server error"
});

}
);

/* =========================
START
========================= */

async function start() {

const server =
app.listen(
PORT,
"0.0.0.0",
() => {
console.log(
"Server listening on port ${PORT}"
);

    console.log(
      "Platform mode: SANDBOX"
    );

    console.log(
      "Real funds enabled: false"
    );
  }
);

const shutdown =
async (signal) => {
console.log(
"${signal} received. Shutting down gracefully..."
);

  server.close(
    async () => {
      try {
        await mongoose.connection.close();
      } catch (error) {
        console.error(
          "MongoDB shutdown error:",
          error
        );
      }

      process.exit(0);
    }
  );
};

process.once(
"SIGTERM",
() => shutdown("SIGTERM")
);

process.once(
"SIGINT",
() => shutdown("SIGINT")
);

try {
await mongoose.connect(
MONGO_URI
);

console.log(
  "DB connected"
);

} catch (error) {
console.error(
"Database connection failed:",
error
);

server.close(
  () => {
    process.exit(1);
  }
);

}
}

start().catch(
(error) => {
console.error(
"Startup failed:",
error
);

process.exit(1);

}
);
