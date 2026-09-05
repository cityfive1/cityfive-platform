"use strict";

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const crypto = require("crypto");

const {
  verifyWebhook,
  normalizeWebhookEvent,
  processBtcWebhook
} = require("./fireblocks");

const app = express();

const PORT = Number(process.env.PORT) || 3000;

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString("hex");

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  "https://cityfive1.github.io";

const PLATFORM_MODE =
  process.env.PLATFORM_MODE || "SANDBOX";

const REAL_FUNDS_ENABLED = false;


// =====================================
// BASIC APP CONFIGURATION
// =====================================

app.set("trust proxy", 1);

app.use(
  cors({
    origin: FRONTEND_ORIGIN,
    credentials: true
  })
);


// =====================================
// FIREBLOCKS WEBHOOK
// IMPORTANT: BEFORE express.json()
// =====================================

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

      await processBtcWebhook(event);

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


// =====================================
// NORMAL JSON BODY
// IMPORTANT: AFTER WEBHOOK ROUTE
// =====================================

app.use(
  express.json({
    limit: "1mb"
  })
);


// =====================================
// SESSION
// =====================================

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 1000 * 60 * 60 * 24 * 7
    }
  })
);


// =====================================
// DATABASE MODELS
// =====================================

const userSchema = new mongoose.Schema(
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
    },

    active: {
      type: Boolean,
      default: true
    }
  },
  {
    timestamps: true
  }
);


const accountSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true
    },

    currency: {
      type: String,
      enum: ["USD", "BTC"],
      required: true
    },

    available: {
      type: Number,
      default: 0
    },

    locked: {
      type: Number,
      default: 0
    }
  },
  {
    timestamps: true
  }
);


const ledgerEntrySchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true
    },

    currency: {
      type: String,
      required: true
    },

    type: {
      type: String,
      required: true
    },

    amount: {
      type: Number,
      required: true
    },

    reference: {
      type: String,
      required: true
    },

    description: {
      type: String,
      default: ""
    }
  },
  {
    timestamps: true
  }
);


const depositSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true
    },

    currency: {
      type: String,
      default: "BTC"
    },

    amount: {
      type: Number,
      default: 0
    },

    status: {
      type: String,
      default: "sandbox_pending"
    },

    reference: {
      type: String,
      unique: true
    },

    address: {
      type: String,
      default: null
    }
  },
  {
    timestamps: true
  }
);


const withdrawalSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true
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
      default: "under_review"
    },

    reference: {
      type: String,
      unique: true
    },

    txid: {
      type: String,
      default: null
    }
  },
  {
    timestamps: true
  }
);


const tradeSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true
    },

    pair: {
      type: String,
      default: "BTC/USD"
    },

    side: {
      type: String,
      enum: ["buy", "sell"],
      required: true
    },

    amount: Number,

    price: Number,

    status: {
      type: String,
      default: "sandbox"
    }
  },
  {
    timestamps: true
  }
);


const kycSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      unique: true
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
    }
  },
  {
    timestamps: true
  }
);


const auditLogSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null
    },

    action: {
      type: String,
      required: true
    },

    details: {
      type: mongoose.Schema.Types.Mixed,
      default: {}
    }
  },
  {
    timestamps: true
  }
);


const User = mongoose.model(
  "User",
  userSchema
);

const Account = mongoose.model(
  "Account",
  accountSchema
);

const LedgerEntry = mongoose.model(
  "LedgerEntry",
  ledgerEntrySchema
);

const Deposit = mongoose.model(
  "Deposit",
  depositSchema
);

const Withdrawal = mongoose.model(
  "Withdrawal",
  withdrawalSchema
);

const Trade = mongoose.model(
  "Trade",
  tradeSchema
);

const KycProfile = mongoose.model(
  "KycProfile",
  kycSchema
);

const AuditLog = mongoose.model(
  "AuditLog",
  auditLogSchema
);


// =====================================
// HELPERS
// =====================================

function makeReference(prefix) {
  return (
    prefix +
    "-" +
    crypto.randomBytes(8).toString("hex")
  ).toUpperCase();
}


async function getCurrentUser(req) {
  if (!req.session.userId) {
    return null;
  }

  return User.findById(
    req.session.userId
  );
}


async function requireLogin(req, res, next) {
  try {
    const user = await getCurrentUser(req);

    if (!user || !user.active) {
      return res.status(401).json({
        error: "Login required"
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Authentication error"
    });
  }
}


async function requireAdmin(req, res, next) {
  try {
    const user = await getCurrentUser(req);

    if (
      !user ||
      !user.active ||
      user.role !== "admin"
    ) {
      return res.status(403).json({
        error: "Admin access required"
      });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      error: "Authorization error"
    });
  }
}


async function writeAudit(
  userId,
  action,
  details = {}
) {
  try {
    await AuditLog.create({
      userId,
      action,
      details
    });
  } catch (error) {
    console.error(
      "Audit log error:",
      error.message
    );
  }
}


// =====================================
// HEALTH / ROOT
// =====================================

app.get("/", (req, res) => {
  res.json({
    service: "CityFive Holdings Ltd",
    status: "online",
    mode: PLATFORM_MODE,
    realFundsEnabled: REAL_FUNDS_ENABLED
  });
});


app.get("/health", (req, res) => {
  res.json({
    status: "ok",
    mode: PLATFORM_MODE,
    realFundsEnabled: REAL_FUNDS_ENABLED
  });
});


// =====================================
// REGISTER
// =====================================

app.post("/register", async (req, res) => {
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

    if (password.length < 8) {
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
        email: normalizedEmail
      });

    if (existing) {
      return res.status(409).json({
        error: "Email already registered"
      });
    }

    const passwordHash =
      await bcrypt.hash(
        password,
        12
      );

    const user =
      await User.create({
        name: String(name).trim(),
        email: normalizedEmail,
        passwordHash
      });

    await Account.create([
      {
        userId: user._id,
        currency: "USD",
        available: 0,
        locked: 0
      },
      {
        userId: user._id,
        currency: "BTC",
        available: 0,
        locked: 0
      }
    ]);

    await KycProfile.create({
      userId: user._id
    });

    await writeAudit(
      user._id,
      "USER_REGISTERED"
    );

    req.session.userId =
      user._id.toString();

    return res.status(201).json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error(
      "Register error:",
      error.message
    );

    return res.status(500).json({
      error: "Registration failed"
    });
  }
});


// =====================================
// LOGIN
// =====================================

app.post("/login", async (req, res) => {
  try {
    const {
      email,
      password
    } = req.body;

    const normalizedEmail =
      String(email || "")
        .trim()
        .toLowerCase();

    const user =
      await User.findOne({
        email: normalizedEmail
      });

    if (!user || !user.active) {
      return res.status(401).json({
        error:
          "Invalid email or password"
      });
    }

    const valid =
      await bcrypt.compare(
        password || "",
        user.passwordHash
      );

    if (!valid) {
      return res.status(401).json({
        error:
          "Invalid email or password"
      });
    }

    req.session.userId =
      user._id.toString();

    await writeAudit(
      user._id,
      "USER_LOGIN"
    );

    return res.json({
      success: true,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error(
      "Login error:",
      error.message
    );

    return res.status(500).json({
      error: "Login failed"
    });
  }
});


// =====================================
// CURRENT USER
// =====================================

app.get(
  "/me",
  requireLogin,
  async (req, res) => {
    try {
      const accounts =
        await Account.find({
          userId: req.user._id
        });

      const kyc =
        await KycProfile.findOne({
          userId: req.user._id
        });

      return res.json({
        user: {
          id: req.user._id,
          name: req.user.name,
          email: req.user.email,
          role: req.user.role
        },

        accounts,

        kyc: kyc
          ? kyc.status
          : "not_started",

        mode: PLATFORM_MODE,

        realFundsEnabled:
          REAL_FUNDS_ENABLED
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error: "Unable to load account"
      });
    }
  }
);


// =====================================
// KYC
// =====================================

app.post(
  "/kyc/start",
  requireLogin,
  async (req, res) => {
    try {
      const profile =
        await KycProfile.findOneAndUpdate(
          {
            userId: req.user._id
          },
          {
            status: "pending"
          },
          {
            new: true,
            upsert: true
          }
        );

      await writeAudit(
        req.user._id,
        "KYC_STARTED"
      );

      return res.json({
        success: true,
        status: profile.status
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error: "Unable to start KYC"
      });
    }
  }
);


// =====================================
// SANDBOX BTC DEPOSIT
// =====================================

app.post(
  "/deposits/btc",
  requireLogin,
  async (req, res) => {
    try {
      const kyc =
        await KycProfile.findOne({
          userId: req.user._id
        });

      if (
        !kyc ||
        kyc.status !== "approved"
      ) {
        return res.status(403).json({
          error:
            "KYC approval is required"
        });
      }

      if (PLATFORM_MODE !== "SANDBOX") {
        return res.status(403).json({
          error:
            "Live BTC deposits are not enabled"
        });
      }

      const reference =
        makeReference("DEMO");

      const deposit =
        await Deposit.create({
          userId: req.user._id,
          currency: "BTC",
          amount: 0,
          status: "sandbox_pending",
          reference
        });

      await writeAudit(
        req.user._id,
        "SANDBOX_BTC_DEPOSIT_CREATED",
        {
          reference
        }
      );

      return res.status(201).json({
        success: true,
        mode: "SANDBOX",
        deposit
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Unable to create sandbox deposit"
      });
    }
  }
);


// =====================================
// BTC WITHDRAWAL
// =====================================

app.post(
  "/withdrawals/btc",
  requireLogin,
  async (req, res) => {
    try {
      const {
        amount,
        address
      } = req.body;

      const numericAmount =
        Number(amount);

      if (
        !Number.isFinite(
          numericAmount
        ) ||
        numericAmount <= 0
      ) {
        return res.status(400).json({
          error: "Invalid amount"
        });
      }

      if (
        !address ||
        String(address).length < 10
      ) {
        return res.status(400).json({
          error:
            "A valid BTC address is required"
        });
      }

      const kyc =
        await KycProfile.findOne({
          userId: req.user._id
        });

      if (
        !kyc ||
        kyc.status !== "approved"
      ) {
        return res.status(403).json({
          error:
            "KYC approval is required"
        });
      }

      const account =
        await Account.findOne({
          userId: req.user._id,
          currency: "BTC"
        });

      if (
        !account ||
        account.available <
          numericAmount
      ) {
        return res.status(400).json({
          error:
            "Insufficient BTC balance"
        });
      }

      account.available -=
        numericAmount;

      account.locked +=
        numericAmount;

      await account.save();

      const reference =
        makeReference("WD");

      const withdrawal =
        await Withdrawal.create({
          userId: req.user._id,
          currency: "BTC",
          amount: numericAmount,
          address: String(address).trim(),
          status:
            "under_review",
          reference
        });

      await writeAudit(
        req.user._id,
        "BTC_WITHDRAWAL_REQUESTED",
        {
          reference,
          amount: numericAmount
        }
      );

      return res.status(201).json({
        success: true,
        mode: PLATFORM_MODE,
        withdrawal
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Unable to create withdrawal"
      });
    }
  }
);


// =====================================
// ACCOUNTS
// =====================================

app.get(
  "/accounts",
  requireLogin,
  async (req, res) => {
    try {
      const accounts =
        await Account.find({
          userId: req.user._id
        });

      return res.json({
        accounts
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Unable to load accounts"
      });
    }
  }
);


// =====================================
// TRANSACTIONS
// =====================================

app.get(
  "/transactions",
  requireLogin,
  async (req, res) => {
    try {
      const [
        ledger,
        deposits,
        withdrawals,
        trades
      ] = await Promise.all([
        LedgerEntry.find({
          userId: req.user._id
        }).sort({ createdAt: -1 }),

        Deposit.find({
          userId: req.user._id
        }).sort({ createdAt: -1 }),

        Withdrawal.find({
          userId: req.user._id
        }).sort({ createdAt: -1 }),

        Trade.find({
          userId: req.user._id
        }).sort({ createdAt: -1 })
      ]);

      return res.json({
        ledger,
        deposits,
        withdrawals,
        trades
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Unable to load transactions"
      });
    }
  }
);


// =====================================
// ADMIN — USERS
// =====================================

app.get(
  "/admin/users",
  requireAdmin,
  async (req, res) => {
    try {
      const users =
        await User.find()
          .select(
            "_id name email role active createdAt"
          )
          .sort({
            createdAt: -1
          });

      return res.json({
        users
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Unable to load users"
      });
    }
  }
);


// =====================================
// ADMIN — KYC
// =====================================

app.get(
  "/admin/kyc",
  requireAdmin,
  async (req, res) => {
    try {
      const profiles =
        await KycProfile.find()
          .sort({
            createdAt: -1
          });

      return res.json({
        profiles
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Unable to load KYC"
      });
    }
  }
);


// =====================================
// ADMIN — APPROVE KYC
// =====================================

app.post(
  "/admin/kyc/:userId/approve",
  requireAdmin,
  async (req, res) => {
    try {
      const profile =
        await KycProfile.findOneAndUpdate(
          {
            userId: req.params.userId
          },
          {
            status: "approved"
          },
          {
            new: true
          }
        );

      if (!profile) {
        return res.status(404).json({
          error:
            "KYC profile not found"
        });
      }

      await writeAudit(
        req.user._id,
        "ADMIN_KYC_APPROVED",
        {
          userId:
            req.params.userId
        }
      );

      return res.json({
        success: true,
        profile
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Unable to approve KYC"
      });
    }
  }
);


// =====================================
// ADMIN — WITHDRAWALS
// =====================================

app.get(
  "/admin/withdrawals",
  requireAdmin,
  async (req, res) => {
    try {
      const withdrawals =
        await Withdrawal.find()
          .sort({
            createdAt: -1
          });

      return res.json({
        withdrawals
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Unable to load withdrawals"
      });
    }
  }
);


// =====================================
// ADMIN — APPROVE WITHDRAWAL
// SANDBOX ONLY
// =====================================

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
        "under_review"
      ) {
        return res.status(400).json({
          error:
            "Withdrawal is not under review"
        });
      }

      const account =
        await Account.findOne({
          userId:
            withdrawal.userId,
          currency: "BTC"
        });

      if (!account) {
        return res.status(404).json({
          error:
            "BTC account not found"
        });
      }

      if (
        account.locked <
        withdrawal.amount
      ) {
        return res.status(400).json({
          error:
            "Locked BTC balance is insufficient"
        });
      }

      account.locked -=
        withdrawal.amount;

      await account.save();

      withdrawal.status =
        "approved_sandbox";

      await withdrawal.save();

      await writeAudit(
        req.user._id,
        "ADMIN_WITHDRAWAL_APPROVED",
        {
          withdrawalId:
            withdrawal._id
        }
      );

      return res.json({
        success: true,
        mode: "SANDBOX",
        withdrawal
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Unable to approve withdrawal"
      });
    }
  }
);


// =====================================
// ADMIN — AUDIT LOG
// =====================================

app.get(
  "/admin/audit",
  requireAdmin,
  async (req, res) => {
    try {
      const logs =
        await AuditLog.find()
          .sort({
            createdAt: -1
          })
          .limit(500);

      return res.json({
        logs
      });
    } catch (error) {
      console.error(error);

      return res.status(500).json({
        error:
          "Unable to load audit logs"
      });
    }
  }
);


// =====================================
// LOGOUT
// =====================================

app.post(
  "/logout",
  (req, res) => {
    req.session.destroy(
      (error) => {
        if (error) {
          return res.status(500).json({
            error:
              "Logout failed"
          });
        }

        res.clearCookie(
          "connect.sid"
        );

        return res.json({
          success: true
        });
      }
    );
  }
);


// =====================================
// ERROR HANDLER
// =====================================

app.use(
  (err, req, res, next) => {
    console.error(
      "Unhandled error:",
      err
    );

    res.status(500).json({
      error:
        "Internal server error"
    });
  }
);


// =====================================
// START SERVER
// =====================================

async function start() {
  try {
    if (!process.env.MONGO_URI) {
      throw new Error(
        "MONGO_URI environment variable is missing"
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
          `Server listening on port ${PORT}`
        );

        console.log(
          `Platform mode: ${PLATFORM_MODE}`
        );

        console.log(
          `Real funds enabled: ${REAL_FUNDS_ENABLED}`
        );
      }
    );
  } catch (error) {
    console.error(
      "Startup error:",
      error.message
    );

    process.exit(1);
  }
}


start();
