
const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const crypto = require("crypto");

const app = express();

app.set("trust proxy", 1);

/*
|--------------------------------------------------------------------------
| CONFIGURATION
|--------------------------------------------------------------------------
*/

const PORT = process.env.PORT || 3000;
const SESSION_SECRET = process.env.SESSION_SECRET;

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  "https://cityfive1.github.io";

const PLATFORM_MODE =
  process.env.PLATFORM_MODE || "SANDBOX";

if (!SESSION_SECRET) {
  console.error(
    "ERROR: SESSION_SECRET environment variable is missing."
  );
}

/*
|--------------------------------------------------------------------------
| SECURITY / CORS
|--------------------------------------------------------------------------
*/

app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    credentials: true
  })
);

app.use(express.json({ limit: "1mb" }));

app.use(
  session({
    name: "cityfive.sid",
    secret: SESSION_SECRET || crypto.randomBytes(32).toString("hex"),
    resave: false,
    saveUninitialized: false,

    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

/*
|--------------------------------------------------------------------------
| BASIC ROUTES
|--------------------------------------------------------------------------
*/

app.get("/", (req, res) => {
  res.json({
    service: "CityFive Holdings Ltd",
    status: "online",
    mode: PLATFORM_MODE,
    realFundsEnabled: false
  });
});

app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    mode: PLATFORM_MODE,
    realFundsEnabled: false,
    database:
      mongoose.connection.readyState === 1
        ? "connected"
        : "disconnected"
  });
});

/*
|--------------------------------------------------------------------------
| HELPERS
|--------------------------------------------------------------------------
*/

function makeReference(prefix) {
  return (
    prefix +
    "-" +
    Date.now() +
    "-" +
    crypto.randomBytes(4).toString("hex").toUpperCase()
  );
}

function requireLogin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      message: "Authentication required"
    });
  }

  next();
}

function requireAdmin(req, res, next) {
  if (!req.session.userId) {
    return res.status(401).json({
      message: "Authentication required"
    });
  }

  if (req.session.role !== "admin") {
    return res.status(403).json({
      message: "Administrator access required"
    });
  }

  next();
}

function safeNumber(value) {
  const number = Number(value);

  if (!Number.isFinite(number)) {
    return null;
  }

  return number;
}

/*
|--------------------------------------------------------------------------
| USER
|--------------------------------------------------------------------------
*/

const UserSchema = new mongoose.Schema(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
      index: true
    },

    passwordHash: {
      type: String,
      required: true
    },

    role: {
      type: String,
      enum: [
        "customer",
        "admin",
        "compliance",
        "operations"
      ],
      default: "customer"
    },

    accountStatus: {
      type: String,
      enum: [
        "pending",
        "active",
        "restricted",
        "frozen",
        "closed"
      ],
      default: "pending"
    },

    kycStatus: {
      type: String,
      enum: [
        "not_started",
        "pending",
        "approved",
        "rejected",
        "review"
      ],
      default: "not_started"
    },

    country: {
      type: String,
      default: ""
    },

    riskLevel: {
      type: String,
      enum: [
        "unknown",
        "low",
        "medium",
        "high"
      ],
      default: "unknown"
    },

    emailVerified: {
      type: Boolean,
      default: false
    },

    mfaEnabled: {
      type: Boolean,
      default: false
    },

    createdAt: {
      type: Date,
      default: Date.now
    },

    updatedAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true
  }
);

const User = mongoose.model("User", UserSchema);

/*
|--------------------------------------------------------------------------
| ACCOUNTS
|--------------------------------------------------------------------------
*/

const AccountSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },

    asset: {
      type: String,
      enum: ["USD", "BTC"],
      required: true
    },

    available: {
      type: Number,
      default: 0,
      min: 0
    },

    pending: {
      type: Number,
      default: 0,
      min: 0
    },

    locked: {
      type: Number,
      default: 0,
      min: 0
    },

    createdAt: {
      type: Date,
      default: Date.now
    }
  }
);

AccountSchema.index(
  {
    userId: 1,
    asset: 1
  },
  {
    unique: true
  }
);

const Account = mongoose.model(
  "Account",
  AccountSchema
);

/*
|--------------------------------------------------------------------------
| LEDGER
|--------------------------------------------------------------------------
|
| The ledger is the financial source of truth.
|
| Positive amount = credit
| Negative amount = debit
|
| Real production deployment should use stronger
| accounting controls and database transactions.
|--------------------------------------------------------------------------
*/

const LedgerEntrySchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },

    accountId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Account",
      required: true
    },

    asset: {
      type: String,
      enum: ["USD", "BTC"],
      required: true
    },

    amount: {
      type: Number,
      required: true
    },

    entryType: {
      type: String,
      enum: [
        "deposit",
        "withdrawal",
        "trade",
        "fee",
        "adjustment",
        "refund"
      ],
      required: true
    },

    reference: {
      type: String,
      required: true,
      unique: true,
      index: true
    },

    description: {
      type: String,
      default: ""
    },

    status: {
      type: String,
      enum: [
        "pending",
        "posted",
        "reversed"
      ],
      default: "posted"
    },

    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },

    createdAt: {
      type: Date,
      default: Date.now
    }
  }
);

const LedgerEntry = mongoose.model(
  "LedgerEntry",
  LedgerEntrySchema
);

/*
|--------------------------------------------------------------------------
| DEPOSITS
|--------------------------------------------------------------------------
*/

const DepositSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },

    asset: {
      type: String,
      enum: ["BTC"],
      required: true
    },

    amount: {
      type: Number,
      default: 0,
      min: 0
    },

    address: {
      type: String,
      default: ""
    },

    txid: {
      type: String,
      default: "",
      index: true
    },

    confirmations: {
      type: Number,
      default: 0,
      min: 0
    },

    requiredConfirmations: {
      type: Number,
      default: 3
    },

    status: {
      type: String,
      enum: [
        "awaiting_address",
        "awaiting_payment",
        "confirming",
        "completed",
        "failed",
        "cancelled"
      ],
      default: "awaiting_address"
    },

    provider: {
      type: String,
      default: ""
    },

    providerReference: {
      type: String,
      default: ""
    },

    createdAt: {
      type: Date,
      default: Date.now
    },

    completedAt: {
      type: Date,
      default: null
    }
  }
);

const Deposit = mongoose.model(
  "Deposit",
  DepositSchema
);

/*
|--------------------------------------------------------------------------
| WITHDRAWALS
|--------------------------------------------------------------------------
*/

const WithdrawalSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },

    asset: {
      type: String,
      enum: ["BTC"],
      required: true
    },

    amount: {
      type: Number,
      required: true,
      min: 0
    },

    destinationAddress: {
      type: String,
      required: true
    },

    networkFee: {
      type: Number,
      default: 0,
      min: 0
    },

    status: {
      type: String,
      enum: [
        "pending",
        "under_review",
        "approved",
        "processing",
        "completed",
        "rejected",
        "cancelled",
        "failed"
      ],
      default: "pending"
    },

    rejectionReason: {
      type: String,
      default: ""
    },

    txid: {
      type: String,
      default: ""
    },

    provider: {
      type: String,
      default: ""
    },

    providerReference: {
      type: String,
      default: ""
    },

    approvedBy: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    },

    approvedAt: {
      type: Date,
      default: null
    },

    createdAt: {
      type: Date,
      default: Date.now
    },

    completedAt: {
      type: Date,
      default: null
    }
  }
);

const Withdrawal = mongoose.model(
  "Withdrawal",
  WithdrawalSchema
);

/*
|--------------------------------------------------------------------------
| TRADES
|--------------------------------------------------------------------------
*/

const TradeSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },

    side: {
      type: String,
      enum: ["buy", "sell"],
      required: true
    },

    baseAsset: {
      type: String,
      enum: ["BTC"],
      default: "BTC"
    },

    quoteAsset: {
      type: String,
      enum: ["USD"],
      default: "USD"
    },

    btcAmount: {
      type: Number,
      required: true,
      min: 0
    },

    usdAmount: {
      type: Number,
      required: true,
      min: 0
    },

    executionPrice: {
      type: Number,
      required: true,
      min: 0
    },

    fee: {
      type: Number,
      default: 0,
      min: 0
    },

    status: {
      type: String,
      enum: [
        "pending",
        "executed",
        "failed",
        "cancelled"
      ],
      default: "pending"
    },

    provider: {
      type: String,
      default: ""
    },

    providerReference: {
      type: String,
      default: ""
    },

    createdAt: {
      type: Date,
      default: Date.now
    }
  }
);

const Trade = mongoose.model(
  "Trade",
  TradeSchema
);

/*
|--------------------------------------------------------------------------
| KYC PROFILE
|--------------------------------------------------------------------------
*/

const KycProfileSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      unique: true
    },

    provider: {
      type: String,
      default: ""
    },

    providerReference: {
      type: String,
      default: ""
    },

    status: {
      type: String,
      enum: [
        "not_started",
        "pending",
        "approved",
        "rejected",
        "review"
      ],
      default: "not_started"
    },

    country: {
      type: String,
      default: ""
    },

    riskLevel: {
      type: String,
      enum: [
        "unknown",
        "low",
        "medium",
        "high"
      ],
      default: "unknown"
    },

    reviewedAt: {
      type: Date,
      default: null
    },

    createdAt: {
      type: Date,
      default: Date.now
    }
  }
);

const KycProfile = mongoose.model(
  "KycProfile",
  KycProfileSchema
);

/*
|--------------------------------------------------------------------------
| AUDIT LOG
|--------------------------------------------------------------------------
*/

const AuditLogSchema = new mongoose.Schema(
  {
    actorUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    },

    targetUserId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      default: null
    },

    action: {
      type: String,
      required: true,
      index: true
    },

    category: {
      type: String,
      enum: [
        "auth",
        "kyc",
        "deposit",
        "withdrawal",
        "trade",
        "admin",
        "account",
        "system"
      ],
      required: true
    },

    reference: {
      type: String,
      default: ""
    },

    ipAddress: {
      type: String,
      default: ""
    },

    userAgent: {
      type: String,
      default: ""
    },

    metadata: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    },

    createdAt: {
      type: Date,
      default: Date.now,
      index: true
    }
  }
);

const AuditLog = mongoose.model(
  "AuditLog",
  AuditLogSchema
);

/*
|--------------------------------------------------------------------------
| AUDIT HELPER
|--------------------------------------------------------------------------
*/

async function writeAudit({
  actorUserId = null,
  targetUserId = null,
  action,
  category,
  reference = "",
  req = null,
  metadata = {}
}) {
  try {
    await AuditLog.create({
      actorUserId,
      targetUserId,
      action,
      category,
      reference,
      ipAddress:
        req?.headers?.["x-forwarded-for"] ||
        req?.socket?.remoteAddress ||
        "",
      userAgent:
        req?.headers?.["user-agent"] || "",
      metadata
    });
  } catch (error) {
    console.error(
      "Audit log error:",
      error
    );
  }
}

/*
|--------------------------------------------------------------------------
| ACCOUNT CREATION HELPER
|--------------------------------------------------------------------------
*/

async function createUserAccounts(userId) {
  await Account.updateOne(
    {
      userId,
      asset: "USD"
    },
    {
      $setOnInsert: {
        userId,
        asset: "USD"
      }
    },
    {
      upsert: true
    }
  );

  await Account.updateOne(
    {
      userId,
      asset: "BTC"
    },
    {
      $setOnInsert: {
        userId,
        asset: "BTC"
      }
    },
    {
      upsert: true
    }
  );
}

/*
|--------------------------------------------------------------------------
| REGISTER
|--------------------------------------------------------------------------
*/

app.post("/register", async (req, res) => {
  try {
    const email =
      String(req.body.email || "")
        .toLowerCase()
        .trim();

    const password =
      String(req.body.password || "");

    const country =
      String(req.body.country || "")
        .trim()
        .toUpperCase();

    if (!email || !password) {
      return res.status(400).json({
        message:
          "Email and password are required."
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        message:
          "Password must be at least 8 characters."
      });
    }

    const existingUser =
      await User.findOne({ email });

    if (existingUser) {
      return res.status(409).json({
        message:
          "An account with this email already exists."
      });
    }

    const passwordHash =
      await bcrypt.hash(password, 12);

    const user = await User.create({
      email,
      passwordHash,
      country,
      accountStatus: "pending",
      kycStatus: "not_started"
    });

    await createUserAccounts(
      user._id
    );

    await KycProfile.create({
      userId: user._id,
      country
    });

    await writeAudit({
      actorUserId: user._id,
      targetUserId: user._id,
      action: "USER_REGISTERED",
      category: "auth",
      req
    });

    res.status(201).json({
      message:
        "Account created successfully.",
      kycStatus:
        user.kycStatus,
      accountStatus:
        user.accountStatus
    });
  } catch (error) {
    console.error(
      "Registration error:",
      error
    );

    res.status(500).json({
      message:
        "Registration failed."
    });
  }
});

/*
|--------------------------------------------------------------------------
| LOGIN
|--------------------------------------------------------------------------
*/

app.post("/login", async (req, res) => {
  try {
    const email =
      String(req.body.email || "")
        .toLowerCase()
        .trim();

    const password =
      String(req.body.password || "");

    const user =
      await User.findOne({ email });

    if (!user) {
      return res.status(401).json({
        message:
          "Invalid email or password."
      });
    }

    const validPassword =
      await bcrypt.compare(
        password,
        user.passwordHash
      );

    if (!validPassword) {
      await writeAudit({
        targetUserId: user._id,
        action: "LOGIN_FAILED",
        category: "auth",
        req
      });

      return res.status(401).json({
        message:
          "Invalid email or password."
      });
    }

    if (
      user.accountStatus === "frozen" ||
      user.accountStatus === "closed"
    ) {
      return res.status(403).json({
        message:
          "This account is currently unavailable."
      });
    }

    req.session.userId =
      user._id.toString();

    req.session.role =
      user.role;

    await writeAudit({
      actorUserId: user._id,
      targetUserId: user._id,
      action: "LOGIN_SUCCESS",
      category: "auth",
      req
    });

    res.json({
      message:
        "Login successful."
    });
  } catch (error) {
    console.error(
      "Login error:",
      error
    );

    res.status(500).json({
      message:
        "Login failed."
    });
  }
});

/*
|--------------------------------------------------------------------------
| CURRENT USER
|--------------------------------------------------------------------------
*/

app.get(
  "/me",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.session.userId
        ).select(
          "email role accountStatus kycStatus country riskLevel emailVerified mfaEnabled createdAt"
        );

      if (!user) {
        req.session.destroy(
          () => {}
        );

        return res.status(401).json({
          message:
            "User not found."
        });
      }

      const accounts =
        await Account.find({
          userId: user._id
        }).select(
          "asset available pending locked"
        );

      res.json({
        email: user.email,
        role: user.role,
        accountStatus:
          user.accountStatus,
        kycStatus:
          user.kycStatus,
        country:
          user.country,
        riskLevel:
          user.riskLevel,
        emailVerified:
          user.emailVerified,
        mfaEnabled:
          user.mfaEnabled,
        accounts,
        mode: PLATFORM_MODE,
        realFundsEnabled: false,
        createdAt:
          user.createdAt
      });
    } catch (error) {
      console.error(
        "Profile error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load account."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| KYC STATUS
|--------------------------------------------------------------------------
*/

app.get(
  "/kyc",
  requireLogin,
  async (req, res) => {
    try {
      const kyc =
        await KycProfile.findOne({
          userId: req.session.userId
        });

      if (!kyc) {
        return res.json({
          status: "not_started"
        });
      }

      res.json({
        status: kyc.status,
        country: kyc.country,
        riskLevel: kyc.riskLevel,
        provider: kyc.provider
      });
    } catch (error) {
      console.error(
        "KYC status error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load KYC status."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| KYC — SANDBOX SUBMISSION
|--------------------------------------------------------------------------
|
| This does NOT perform real identity verification.
| A real provider will be connected later.
|--------------------------------------------------------------------------
*/

app.post(
  "/kyc/start",
  requireLogin,
  async (req, res) => {
    try {
      const country =
        String(req.body.country || "")
          .trim()
          .toUpperCase();

      if (!country) {
        return res.status(400).json({
          message:
            "Country is required."
        });
      }

      await KycProfile.updateOne(
        {
          userId: req.session.userId
        },
        {
          $set: {
            country,
            status: "pending"
          }
        },
        {
          upsert: true
        }
      );

      await User.updateOne(
        {
          _id: req.session.userId
        },
        {
          $set: {
            country,
            kycStatus: "pending"
          }
        }
      );

      await writeAudit({
        actorUserId:
          req.session.userId,
        targetUserId:
          req.session.userId,
        action: "KYC_STARTED",
        category: "kyc",
        req
      });

      res.json({
        message:
          "KYC application started.",
        status: "pending",
        sandbox: true
      });
    } catch (error) {
      console.error(
        "KYC start error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to start KYC."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| BTC DEPOSIT ADDRESS
|--------------------------------------------------------------------------
|
| SANDBOX ONLY.
|
| This endpoint deliberately does NOT generate a real
| Bitcoin address and does NOT receive real BTC.
|
| Later, this will call the approved custody provider.
|--------------------------------------------------------------------------
*/

app.post(
  "/deposits/btc",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.session.userId
        );

      if (!user) {
        return res.status(404).json({
          message:
            "User not found."
        });
      }

      if (
        user.kycStatus !== "approved"
      ) {
        return res.status(403).json({
          message:
            "KYC approval is required before deposits are enabled."
        });
      }

      /*
       * Real provider integration intentionally
       * disabled in sandbox mode.
       */

      const reference =
        makeReference("DEP");

      const deposit =
        await Deposit.create({
          userId: user._id,
          asset: "BTC",
          amount: 0,
          address: "",
          status:
            "awaiting_address",
          provider: "SANDBOX"
        });

      await writeAudit({
        actorUserId:
          user._id,
        targetUserId:
          user._id,
        action: "BTC_DEPOSIT_REQUESTED",
        category: "deposit",
        reference,
        req
      });

      res.json({
        message:
          "BTC deposit infrastructure is in sandbox mode. No real BTC address has been issued.",
        depositId:
          deposit._id,
        status:
          deposit.status,
        sandbox: true,
        realFundsEnabled: false
      });
    } catch (error) {
      console.error(
        "Deposit error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to create deposit."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| USER DEPOSITS
|--------------------------------------------------------------------------
*/

app.get(
  "/deposits",
  requireLogin,
  async (req, res) => {
    try {
      const deposits =
        await Deposit.find({
          userId: req.session.userId
        })
          .sort({
            createdAt: -1
          })
          .limit(100);

      res.json({
        deposits
      });
    } catch (error) {
      console.error(
        "Deposit history error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load deposits."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| WITHDRAWAL REQUEST
|--------------------------------------------------------------------------
|
| SANDBOX ONLY.
| No BTC is broadcast.
|--------------------------------------------------------------------------
*/

app.post(
  "/withdrawals/btc",
  requireLogin,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.session.userId
        );

      if (!user) {
        return res.status(404).json({
          message:
            "User not found."
        });
      }

      if (
        user.kycStatus !== "approved"
      ) {
        return res.status(403).json({
          message:
            "KYC approval is required before withdrawals are enabled."
        });
      }

      const amount =
        safeNumber(
          req.body.amount
        );

      const destinationAddress =
        String(
          req.body.destinationAddress ||
            ""
        ).trim();

      if (
        amount === null ||
        amount <= 0
      ) {
        return res.status(400).json({
          message:
            "A valid BTC amount is required."
        });
      }

      if (
        !destinationAddress
      ) {
        return res.status(400).json({
          message:
            "A BTC destination address is required."
        });
      }

      const account =
        await Account.findOne({
          userId: user._id,
          asset: "BTC"
        });

      if (!account) {
        return res.status(404).json({
          message:
            "BTC account not found."
        });
      }

      if (
        account.available < amount
      ) {
        return res.status(400).json({
          message:
            "Insufficient available BTC."
        });
      }

      /*
       * Sandbox:
       *
       * We do not actually lock or broadcast funds yet.
       * This prevents accidental real-money movement.
       */

      const withdrawal =
        await Withdrawal.create({
          userId: user._id,
          asset: "BTC",
          amount,
          destinationAddress,
          status: "under_review",
          provider: "SANDBOX"
        });

      await writeAudit({
        actorUserId:
          user._id,
        targetUserId:
          user._id,
        action:
          "BTC_WITHDRAWAL_REQUESTED",
        category:
          "withdrawal",
        reference:
          withdrawal._id.toString(),
        req,
        metadata: {
          amount,
          sandbox: true
        }
      });

      res.status(201).json({
        message:
          "Withdrawal request created in sandbox mode. No real BTC has been sent.",
        withdrawalId:
          withdrawal._id,
        status:
          withdrawal.status,
        sandbox: true,
        realFundsEnabled: false
      });
    } catch (error) {
      console.error(
        "Withdrawal error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to create withdrawal."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| USER WITHDRAWALS
|--------------------------------------------------------------------------
*/

app.get(
  "/withdrawals",
  requireLogin,
  async (req, res) => {
    try {
      const withdrawals =
        await Withdrawal.find({
          userId: req.session.userId
        })
          .sort({
            createdAt: -1
          })
          .limit(100);

      res.json({
        withdrawals
      });
    } catch (error) {
      console.error(
        "Withdrawal history error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load withdrawals."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| TRANSACTIONS / LEDGER
|--------------------------------------------------------------------------
*/

app.get(
  "/transactions",
  requireLogin,
  async (req, res) => {
    try {
      const entries =
        await LedgerEntry.find({
          userId: req.session.userId
        })
          .sort({
            createdAt: -1
          })
          .limit(100);

      res.json({
        transactions: entries
      });
    } catch (error) {
      console.error(
        "Transaction error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load transactions."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| ACCOUNTS
|--------------------------------------------------------------------------
*/

app.get(
  "/accounts",
  requireLogin,
  async (req, res) => {
    try {
      const accounts =
        await Account.find({
          userId: req.session.userId
        }).select(
          "asset available pending locked"
        );

      res.json({
        accounts
      });
    } catch (error) {
      console.error(
        "Account error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load accounts."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| ADMIN — CUSTOMERS
|--------------------------------------------------------------------------
*/

app.get(
  "/admin/users",
  requireAdmin,
  async (req, res) => {
    try {
      const users =
        await User.find({})
          .select(
            "email role accountStatus kycStatus country riskLevel createdAt"
          )
          .sort({
            createdAt: -1
          })
          .limit(500);

      res.json({
        users
      });
    } catch (error) {
      console.error(
        "Admin users error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load users."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| ADMIN — KYC REVIEW
|--------------------------------------------------------------------------
*/

app.post(
  "/admin/kyc/:userId",
  requireAdmin,
  async (req, res) => {
    try {
      const {
        status,
        riskLevel
      } = req.body;

      const allowedStatuses = [
        "approved",
        "rejected",
        "review"
      ];

      const allowedRiskLevels = [
        "low",
        "medium",
        "high",
        "unknown"
      ];

      if (
        !allowedStatuses.includes(
          status
        )
      ) {
        return res.status(400).json({
          message:
            "Invalid KYC status."
        });
      }

      if (
        riskLevel &&
        !allowedRiskLevels.includes(
          riskLevel
        )
      ) {
        return res.status(400).json({
          message:
            "Invalid risk level."
        });
      }

      const user =
        await User.findById(
          req.params.userId
        );

      if (!user) {
        return res.status(404).json({
          message:
            "User not found."
        });
      }

      user.kycStatus =
        status;

      if (riskLevel) {
        user.riskLevel =
          riskLevel;
      }

      if (
        status === "approved"
      ) {
        user.accountStatus =
          "active";
      }

      await user.save();

      await KycProfile.updateOne(
        {
          userId: user._id
        },
        {
          $set: {
            status,
            riskLevel:
              riskLevel ||
              user.riskLevel,
            reviewedAt:
              new Date()
          }
        },
        {
          upsert: true
        }
      );

      await writeAudit({
        actorUserId:
          req.session.userId,
        targetUserId:
          user._id,
        action:
          "KYC_STATUS_CHANGED",
        category: "kyc",
        req,
        metadata: {
          status,
          riskLevel:
            riskLevel ||
            user.riskLevel
        }
      });

      res.json({
        message:
          "KYC status updated.",
        userId:
          user._id,
        kycStatus:
          user.kycStatus,
        riskLevel:
          user.riskLevel
      });
    } catch (error) {
      console.error(
        "Admin KYC error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to update KYC."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| ADMIN — WITHDRAWALS
|--------------------------------------------------------------------------
*/

app.get(
  "/admin/withdrawals",
  requireAdmin,
  async (req, res) => {
    try {
      const withdrawals =
        await Withdrawal.find({})
          .populate(
            "userId",
            "email"
          )
          .sort({
            createdAt: -1
          })
          .limit(500);

      res.json({
        withdrawals
      });
    } catch (error) {
      console.error(
        "Admin withdrawal error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load withdrawals."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| ADMIN — APPROVE WITHDRAWAL
|--------------------------------------------------------------------------
|
| Sandbox only.
| Approval does NOT send BTC.
|--------------------------------------------------------------------------
*/

app.post(
  "/admin/withdrawals/:withdrawalId/approve",
  requireAdmin,
  async (req, res) => {
    try {
      const withdrawal =
        await Withdrawal.findById(
          req.params.withdrawalId
        );

      if (!withdrawal) {
        return res.status(404).json({
          message:
            "Withdrawal not found."
        });
      }

      if (
        withdrawal.status !==
        "under_review"
      ) {
        return res.status(400).json({
          message:
            "Withdrawal is not awaiting review."
        });
      }

      withdrawal.status =
        "approved";

      withdrawal.approvedBy =
        req.session.userId;

      withdrawal.approvedAt =
        new Date();

      await withdrawal.save();

      await writeAudit({
        actorUserId:
          req.session.userId,
        targetUserId:
          withdrawal.userId,
        action:
          "WITHDRAWAL_APPROVED",
        category:
          "withdrawal",
        reference:
          withdrawal._id.toString(),
        req,
        metadata: {
          sandbox: true,
          amount:
            withdrawal.amount
        }
      });

      res.json({
        message:
          "Withdrawal approved in sandbox mode. No BTC has been sent.",
        withdrawal
      });
    } catch (error) {
      console.error(
        "Withdrawal approval error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to approve withdrawal."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| ADMIN — REJECT WITHDRAWAL
|--------------------------------------------------------------------------
*/

app.post(
  "/admin/withdrawals/:withdrawalId/reject",
  requireAdmin,
  async (req, res) => {
    try {
      const reason =
        String(
          req.body.reason || ""
        ).trim();

      const withdrawal =
        await Withdrawal.findById(
          req.params.withdrawalId
        );

      if (!withdrawal) {
        return res.status(404).json({
          message:
            "Withdrawal not found."
        });
      }

      if (
        ![
          "pending",
          "under_review"
        ].includes(
          withdrawal.status
        )
      ) {
        return res.status(400).json({
          message:
            "Withdrawal cannot be rejected in its current state."
        });
      }

      withdrawal.status =
        "rejected";

      withdrawal.rejectionReason =
        reason;

      await withdrawal.save();

      await writeAudit({
        actorUserId:
          req.session.userId,
        targetUserId:
          withdrawal.userId,
        action:
          "WITHDRAWAL_REJECTED",
        category:
          "withdrawal",
        reference:
          withdrawal._id.toString(),
        req,
        metadata: {
          reason
        }
      });

      res.json({
        message:
          "Withdrawal rejected.",
        withdrawal
      });
    } catch (error) {
      console.error(
        "Withdrawal rejection error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to reject withdrawal."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| ADMIN — AUDIT LOG
|--------------------------------------------------------------------------
*/

app.get(
  "/admin/audit-logs",
  requireAdmin,
  async (req, res) => {
    try {
      const logs =
        await AuditLog.find({})
          .populate(
            "actorUserId",
            "email"
          )
          .populate(
            "targetUserId",
            "email"
          )
          .sort({
            createdAt: -1
          })
          .limit(500);

      res.json({
        logs
      });
    } catch (error) {
      console.error(
        "Audit log error:",
        error
      );

      res.status(500).json({
        message:
          "Unable to load audit logs."
      });
    }
  }
);

/*
|--------------------------------------------------------------------------
| ADMIN — SYSTEM STATUS
|--------------------------------------------------------------------------
*/

app.get(
  "/admin/status",
  requireAdmin,
  async (req, res) => {
    res.json({
      platform:
        "CityFive Holdings Ltd",
      mode:
        PLATFORM_MODE,
      realFundsEnabled:
        false,
      custodyProvider:
        "NOT_CONNECTED",
      kycProvider:
        "NOT_CONNECTED",
      bitcoinNetwork:
        "SANDBOX / NOT_CONNECTED",
      message:
        "Real customer funds are disabled."
    });
  }
);

/*
|--------------------------------------------------------------------------
| LOGOUT
|--------------------------------------------------------------------------
*/

app.post(
  "/logout",
  async (req, res) => {
    const userId =
      req.session.userId;

    if (userId) {
      await writeAudit({
        actorUserId: userId,
        targetUserId: userId,
        action: "LOGOUT",
        category: "auth",
        req
      });
    }

    req.session.destroy(
      (error) => {
        if (error) {
          console.error(
            "Logout error:",
            error
          );

          return res.status(500).json({
            message:
              "Logout failed."
          });
        }

        res.clearCookie(
          "cityfive.sid"
        );

        res.json({
          message:
            "Logged out successfully."
        });
      }
    );
  }
);

/*
|--------------------------------------------------------------------------
| ERROR HANDLER
|--------------------------------------------------------------------------
*/

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

    res.status(500).json({
      message:
        "Internal server error."
    });
  }
);

/*
|--------------------------------------------------------------------------
| DATABASE + SERVER
|--------------------------------------------------------------------------
*/

async function startServer() {
  try {
    if (!process.env.MONGO_URI) {
      throw new Error(
        "MONGO_URI environment variable is missing."
      );
    }

    await mongoose.connect(
      process.env.MONGO_URI
    );

    console.log(
      "DB connected"
    );

    app.listen(
      PORT,
      "0.0.0.0",
      () => {
        console.log(
          "Server running on port " +
            PORT
        );

        console.log(
          "Platform mode: " +
            PLATFORM_MODE
        );

        console.log(
          "Real funds enabled: false"
        );
      }
    );
  } catch (error) {
    console.error(
      "Startup error:",
      error
    );

    process.exit(1);
  }
}

startServer();
