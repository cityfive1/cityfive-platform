
// CITYFIVE HOLDINGS LTD — SANDBOX BACKEND
"use strict";

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const session = require("express-session");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const {
  verifyWebhook,
  normalizeWebhookEvent,
  processBtcWebhook
} = require("./fireblocks");

const app = express();

const PORT = Number(process.env.PORT) || 3000;
const MONGO_URI = process.env.MONGO_URI || "";

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString("hex");

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  "https://cityfive1.github.io";

const PLATFORM_MODE =
  process.env.PLATFORM_MODE || "SANDBOX";

// IMPORTANT: Real funds remain disabled.
const REAL_FUNDS_ENABLED = false;

const ALLOWED_ORIGINS = [
  "https://cityfive1.github.io",
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  FRONTEND_ORIGIN
].filter(Boolean);

/* =========================================================
   CORS
   ========================================================= */

const corsOptions = {
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }

    return callback(new Error("CORS origin not allowed"));
  },

  credentials: true,

  methods: [
    "GET",
    "HEAD",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "OPTIONS"
  ],

  allowedHeaders: [
    "Content-Type",
    "Authorization"
  ],

  optionsSuccessStatus: 204
};

app.use(cors(corsOptions));
app.options("*", cors(corsOptions));

app.set("trust proxy", 1);

/* =========================================================
   FIREBLOCKS WEBHOOK
   Raw body must be received before JSON parser.
   ========================================================= */

app.post(
  "/webhooks/fireblocks",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    try {
      const signature =
        req.headers["fireblocks-webhook-signature"];

      const valid = await verifyWebhook(
        req.body,
        signature
      );

      if (!valid) {
        return res.status(401).json({
          error: "Invalid webhook signature"
        });
      }

      const event = JSON.parse(
        req.body.toString("utf8")
      );

      const normalized =
        normalizeWebhookEvent(event);

      const result =
        await processBtcWebhook(event);

      console.log(
        "Fireblocks webhook received:",
        normalized
      );

      return res.json({
        ok: true,
        ...result
      });
    } catch (error) {
      console.error(
        "Webhook error:",
        error.message
      );

      return res.status(400).json({
        error: "Invalid webhook"
      });
    }
  }
);

/* =========================================================
   BODY PARSERS
   ========================================================= */

app.use(
  express.json({
    limit: "1mb"
  })
);

app.use(
  express.urlencoded({
    extended: true,
    limit: "1mb"
  })
);

/* =========================================================
   SESSION
   ========================================================= */

app.use(
  session({
    name: "cityfive.sid",

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

/* =========================================================
   USER MODEL
   ========================================================= */

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100
    },

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
      enum: ["user", "admin"],
      default: "user"
    },

    kycStatus: {
      type: String,
      enum: [
        "not_started",
        "pending",
        "approved",
        "rejected"
      ],
      default: "not_started"
    },

    accountStatus: {
      type: String,
      enum: [
        "pending",
        "active",
        "suspended"
      ],
      default: "pending"
    },

    lastLoginAt: {
      type: Date,
      default: null
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

const User = mongoose.model(
  "User",
  userSchema
);

/* =========================================================
   AUTH TOKEN MODEL
   ========================================================= */

const authTokenSchema = new mongoose.Schema(
  {
    tokenHash: {
      type: String,
      required: true,
      unique: true,
      index: true
    },

    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true
    },

    expiresAt: {
      type: Date,
      required: true,
      index: true
    }
  },
  {
    timestamps: true
  }
);

const AuthToken = mongoose.model(
  "AuthToken",
  authTokenSchema
);

/* =========================================================
   ACCOUNT MODEL
   ========================================================= */

const accountSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      index: true
    },

    currency: {
      type: String,
      enum: [
        "CAD",
        "USD",
        "BTC"
      ],
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

accountSchema.index(
  {
    userId: 1,
    currency: 1
  },
  {
    unique: true
  }
);

const Account = mongoose.model(
  "Account",
  accountSchema
);

/* =========================================================
   KYC MODEL
   ========================================================= */

const kycSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      required: true,
      unique: true,
      index: true
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

const KycProfile = mongoose.model(
  "KycProfile",
  kycSchema
);

/* =========================================================
   DEPOSIT MODEL
   ========================================================= */

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
      required: true
    },

    status: {
      type: String,
      enum: [
        "pending",
        "sandbox_completed",
        "confirmed",
        "rejected"
      ],
      default: "pending"
    },

    reference: {
      type: String,
      required: true,
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

const Deposit = mongoose.model(
  "Deposit",
  depositSchema
);

/* =========================================================
   WITHDRAWAL MODEL
   ========================================================= */

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
      enum: [
        "under_review",
        "approved_sandbox",
        "rejected",
        "completed"
      ],
      default: "under_review"
    },

    reference: {
      type: String,
      required: true,
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

const Withdrawal = mongoose.model(
  "Withdrawal",
  withdrawalSchema
);

/* =========================================================
   LEDGER MODEL
   ========================================================= */

const ledgerSchema = new mongoose.Schema(
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
      enum: [
        "sandbox_deposit",
        "sandbox_withdrawal",
        "adjustment"
      ],
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
      required: true
    }
  },
  {
    timestamps: true
  }
);

const Ledger = mongoose.model(
  "Ledger",
  ledgerSchema
);

/* =========================================================
   AUDIT LOG MODEL
   ========================================================= */

const auditSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      default: null,
      index: true
    },

    action: {
      type: String,
      required: true
    },

    details: {
      type: Object,
      default: {}
    }
  },
  {
    timestamps: true
  }
);

const AuditLog = mongoose.model(
  "AuditLog",
  auditSchema
);

/* =========================================================
   HELPERS
   ========================================================= */

function makeReference(prefix) {
  return (
    prefix +
    "_" +
    Date.now().toString(36) +
    "_" +
    crypto.randomBytes(5).toString("hex")
  ).toUpperCase();
}

function hashToken(token) {
  return crypto
    .createHash("sha256")
    .update(token)
    .digest("hex");
}

function createAuthToken() {
  return crypto
    .randomBytes(48)
    .toString("base64url");
}

async function issueAuthToken(userId) {
  const token = createAuthToken();

  await AuthToken.create({
    tokenHash: hashToken(token),

    userId,

    expiresAt: new Date(
      Date.now() +
      1000 * 60 * 60 * 24 * 7
    )
  });

  return token;
}

async function revokeAuthToken(token) {
  if (!token) {
    return;
  }

  await AuthToken.deleteOne({
    tokenHash: hashToken(token)
  });
}

function getBearerToken(req) {
  const header =
    req.headers.authorization;

  if (
    !header ||
    typeof header !== "string"
  ) {
    return null;
  }

  if (
    !header
      .toLowerCase()
      .startsWith("bearer ")
  ) {
    return null;
  }

  return header
    .substring(7)
    .trim();
}

async function getCurrentUser(req) {
  const bearer =
    getBearerToken(req);

  /* Token authentication */
  if (bearer) {
    const tokenRecord =
      await AuthToken.findOne({
        tokenHash: hashToken(bearer),

        expiresAt: {
          $gt: new Date()
        }
      });

    if (!tokenRecord) {
      return null;
    }

    const user =
      await User.findById(
        tokenRecord.userId
      );

    if (
      !user ||
      !user.active
    ) {
      return null;
    }

    return user;
  }

  /* Session authentication fallback */
  if (req.session?.userId) {
    const user =
      await User.findById(
        req.session.userId
      );

    if (
      user &&
      user.active
    ) {
      return user;
    }
  }

  return null;
}

async function requireLogin(
  req,
  res,
  next
) {
  try {
    const user =
      await getCurrentUser(req);

    if (!user) {
      return res.status(401).json({
        error: "Login required"
      });
    }

    req.user = user;

    next();
  } catch (error) {
    console.error(
      "Authentication error:",
      error.message
    );

    return res.status(500).json({
      error: "Authentication failed"
    });
  }
}

async function requireAdmin(
  req,
  res,
  next
) {
  try {
    const user =
      await getCurrentUser(req);

    if (!user) {
      return res.status(401).json({
        error: "Login required"
      });
    }

    if (user.role !== "admin") {
      return res.status(403).json({
        error:
          "Administrator access required"
      });
    }

    req.user = user;

    next();
  } catch (error) {
    console.error(
      "Admin authentication error:",
      error.message
    );

    return res.status(500).json({
      error: "Authentication failed"
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
      userId: userId || null,
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

async function ensureUserAccounts(
  userId
) {
  for (
    const currency of [
      "CAD",
      "BTC"
    ]
  ) {
    const existing =
      await Account.findOne({
        userId,
        currency
      });

    if (!existing) {
      await Account.create({
        userId,
        currency,
        available: 0,
        locked: 0
      });
    }
  }
}

function publicUser(user) {
  return {
    id: user._id.toString(),

    name: user.name,

    email: user.email,

    role: user.role,

    kycStatus:
      user.kycStatus,

    accountStatus:
      user.accountStatus
  };
}

/* =========================================================
   PUBLIC ROUTES
   ========================================================= */

app.get(
  "/",
  (req, res) => {
    res.json({
      service:
        "CityFive Holdings Ltd",

      status: "online",

      mode:
        PLATFORM_MODE,

      realFundsEnabled:
        REAL_FUNDS_ENABLED
    });
  }
);

app.get(
  "/health",
  (req, res) => {
    res.json({
      ok: true,

      mode:
        PLATFORM_MODE,

      realFundsEnabled:
        REAL_FUNDS_ENABLED,

      frontendOrigin:
        FRONTEND_ORIGIN
    });
  }
);

/* =========================================================
   REGISTER
   ========================================================= */

app.post(
  "/register",
  async (req, res) => {
    try {
      const name =
        String(
          req.body?.name || ""
        ).trim();

      const email =
        String(
          req.body?.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body?.password || ""
        );

      if (name.length < 2) {
        return res.status(400).json({
          error:
            "Please enter your full name."
        });
      }

      if (
        !email ||
        !email.includes("@")
      ) {
        return res.status(400).json({
          error:
            "Please enter a valid email address."
        });
      }

      if (password.length < 8) {
        return res.status(400).json({
          error:
            "Password must be at least 8 characters."
        });
      }

      const existing =
        await User.findOne({
          email
        });

      if (existing) {
        return res.status(409).json({
          error:
            "Email already registered"
        });
      }

      const passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      const user =
        await User.create({
          name,
          email,
          passwordHash,
          role: "user",
          kycStatus: "not_started",
          accountStatus: "active",
          active: true
        });

      await ensureUserAccounts(
        user._id
      );

      await KycProfile.create({
        userId: user._id,
        status: "not_started"
      });

      const token =
        await issueAuthToken(
          user._id
        );

      req.session.userId =
        user._id.toString();

      await new Promise(
        (resolve, reject) => {
          req.session.save(
            (err) => {
              if (err) {
                reject(err);
              } else {
                resolve();
              }
            }
          );
        }
      );

      await writeAudit(
        user._id,
        "USER_REGISTERED",
        {
          mode:
            PLATFORM_MODE
        }
      );

      return res
        .status(201)
        .json({
          ok: true,

          token,

          user:
            publicUser(user),

          mode:
            PLATFORM_MODE,

          realFundsEnabled:
            REAL_FUNDS_ENABLED
        });
    } catch (error) {
      console.error(
        "Registration error:",
        error
      );

      if (
        error.code === 11000
      ) {
        return res.status(409).json({
          error:
            "Email already registered"
        });
      }

      return res.status(500).json({
        error:
          "Registration failed"
      });
    }
  }
);

/* =========================================================
   LOGIN
   ========================================================= */

app.post(
  "/login",
  async (req, res) => {
    try {
      const email =
        String(
          req.body?.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body?.password || ""
        );

      if (
        !email ||
        !password
      ) {
        return res.status(400).json({
          error:
            "Email and password are required."
        });
      }

      const user =
        await User.findOne({
          email
        });

      if (
        !user ||
        !user.active
      ) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      const passwordMatches =
        await bcrypt.compare(
          password,
          user.passwordHash
        );

      if (!passwordMatches) {
        return res.status(401).json({
          error:
            "Invalid email or password."
        });
      }

      user.lastLoginAt =
        new Date();

      if (
        user.accountStatus ===
        "pending"
      ) {
        user.accountStatus =
          "active";
      }

      await user.save();

      await ensureUserAccounts(
        user._id
      );

      const token =
        await issueAuthToken(
          user._id
        );

      req.session.userId =
        user._id.toString();

      await new Promise(
        (resolve, reject) => {
          req.session.save(
            (err) => {
              if (err) {
                reject(err);
              } else {
                resolve();
              }
            }
          );
        }
      );

      await writeAudit(
        user._id,
        "USER_LOGIN",
        {
          mode:
            PLATFORM_MODE
        }
      );

      return res.json({
        ok: true,

        token,

        user:
          publicUser(user),

        mode:
          PLATFORM_MODE,

        realFundsEnabled:
          REAL_FUNDS_ENABLED
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

/* =========================================================
   CURRENT USER
   ========================================================= */

app.get(
  "/me",
  requireLogin,
  async (req, res) => {
    try {
      await ensureUserAccounts(
        req.user._id
      );

      const accounts =
        await Account.find({
          userId:
            req.user._id
        }).sort({
          currency: 1
        });

      return res.json({
        user:
          publicUser(
            req.user
          ),

        accounts,

        mode:
          PLATFORM_MODE,

        realFundsEnabled:
          REAL_FUNDS_ENABLED
      });
    } catch (error) {
      console.error(
        "ME error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load account."
      });
    }
  }
);

/* =========================================================
   KYC START
   ========================================================= */

app.post(
  "/kyc/start",
  requireLogin,
  async (req, res) => {
    try {
      const kyc =
        await KycProfile.findOneAndUpdate(
          {
            userId:
              req.user._id
          },

          {
            status:
              "pending"
          },

          {
            new: true,
            upsert: true
          }
        );

      req.user.kycStatus =
        "pending";

      await req.user.save();

      await writeAudit(
        req.user._id,
        "KYC_STARTED"
      );

      return res.json({
        ok: true,

        status:
          kyc.status,

        message:
          "Sandbox KYC workflow started."
      });
    } catch (error) {
      console.error(
        "KYC error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to start KYC."
      });
    }
  }
);

/* =========================================================
   SANDBOX BTC DEPOSIT
   ========================================================= */

app.post(
  "/deposits/btc",
  requireLogin,
  async (req, res) => {
    try {
      if (
        PLATFORM_MODE !==
        "SANDBOX"
      ) {
        return res.status(403).json({
          error:
            "Sandbox deposit endpoint is disabled."
        });
      }

      if (
        req.user.kycStatus !==
        "approved"
      ) {
        return res.status(403).json({
          error:
            "KYC approval is required before creating a simulated deposit."
        });
      }

      const amount =
        Number(
          req.body?.amount
        );

      if (
        !Number.isFinite(
          amount
        ) ||
        amount <= 0
      ) {
        return res.status(400).json({
          error:
            "Enter a valid BTC amount."
        });
      }

      if (amount > 100) {
        return res.status(400).json({
          error:
            "Sandbox deposit limit is 100 BTC."
        });
      }

      const reference =
        makeReference("DEP");

      const deposit =
        await Deposit.create({
          userId:
            req.user._id,

          currency:
            "BTC",

          amount,

          status:
            "sandbox_completed",

          reference,

          address:
            "SANDBOX-BTC-ADDRESS"
        });

      const account =
        await Account.findOne({
          userId:
            req.user._id,

          currency:
            "BTC"
        });

      if (!account) {
        return res.status(500).json({
          error:
            "BTC account not found."
        });
      }

      account.available +=
        amount;

      await account.save();

      await Ledger.create({
        userId:
          req.user._id,

        currency:
          "BTC",

        type:
          "sandbox_deposit",

        amount,

        reference,

        description:
          "Simulated sandbox BTC deposit. No real Bitcoin was transferred."
      });

      await writeAudit(
        req.user._id,
        "SANDBOX_BTC_DEPOSIT",
        {
          amount,
          reference
        }
      );

      return res
        .status(201)
        .json({
          ok: true,

          mode:
            "SANDBOX",

          realFundsEnabled:
            false,

          deposit,

          message:
            "Simulated BTC deposit completed. No real Bitcoin was transferred."
        });
    } catch (error) {
      console.error(
        "Deposit error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to create simulated deposit."
      });
    }
  }
);

/* =========================================================
   SANDBOX BTC WITHDRAWAL
   ========================================================= */

app.post(
  "/withdrawals/btc",
  requireLogin,
  async (req, res) => {
    try {
      if (
        PLATFORM_MODE !==
        "SANDBOX"
      ) {
        return res.status(403).json({
          error:
            "Sandbox withdrawal endpoint is disabled."
        });
      }

      if (
        req.user.kycStatus !==
        "approved"
      ) {
        return res.status(403).json({
          error:
            "KYC approval is required before creating a simulated withdrawal."
        });
      }

      const amount =
        Number(
          req.body?.amount
        );

      const address =
        String(
          req.body?.address || ""
        ).trim();

      if (
        !Number.isFinite(
          amount
        ) ||
        amount <= 0
      ) {
        return res.status(400).json({
          error:
            "Enter a valid BTC amount."
        });
      }

      if (!address) {
        return res.status(400).json({
          error:
            "Enter a Bitcoin address."
        });
      }

      if (
        address.length < 10 ||
        address.length > 200
      ) {
        return res.status(400).json({
          error:
            "Enter a valid-looking Bitcoin address."
        });
      }

      const account =
        await Account.findOne({
          userId:
            req.user._id,

          currency:
            "BTC"
        });

      if (!account) {
        return res.status(404).json({
          error:
            "BTC account not found."
        });
      }

      if (
        account.available <
        amount
      ) {
        return res.status(400).json({
          error:
            "Insufficient simulated BTC balance."
        });
      }

      const reference =
        makeReference("WDR");

      account.available -=
        amount;

      account.locked +=
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
            "under_review",

          reference
        });

      await Ledger.create({
        userId:
          req.user._id,

        currency:
          "BTC",

        type:
          "sandbox_withdrawal",

        amount:
          -amount,

        reference,

        description:
          "Simulated sandbox BTC withdrawal request. No real Bitcoin was transferred."
      });

      await writeAudit(
        req.user._id,
        "SANDBOX_BTC_WITHDRAWAL_CREATED",
        {
          amount,
          reference
        }
      );

      return res
        .status(201)
        .json({
          ok: true,

          mode:
            "SANDBOX",

          realFundsEnabled:
            false,

          withdrawal,

          message:
            "Simulated withdrawal submitted for sandbox review. No real Bitcoin was transferred."
        });
    } catch (error) {
      console.error(
        "Withdrawal error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to create simulated withdrawal."
      });
    }
  }
);

/* =========================================================
   ACCOUNTS
   ========================================================= */

app.get(
  "/accounts",
  requireLogin,
  async (req, res) => {
    try {
      await ensureUserAccounts(
        req.user._id
      );

      const accounts =
        await Account.find({
          userId:
            req.user._id
        }).sort({
          currency: 1
        });

      return res.json({
        accounts
      });
    } catch (error) {
      return res.status(500).json({
        error:
          "Unable to load accounts."
      });
    }
  }
);

/* =========================================================
   TRANSACTIONS
   ========================================================= */

app.get(
  "/transactions",
  requireLogin,
  async (req, res) => {
    try {
      const deposits =
        await Deposit.find({
          userId:
            req.user._id
        })
          .sort({
            createdAt: -1
          })
          .limit(50)
          .lean();

      const withdrawals =
        await Withdrawal.find({
          userId:
            req.user._id
        })
          .sort({
            createdAt: -1
          })
          .limit(50)
          .lean();

      const transactions = [
        ...deposits.map(
          (item) => ({
            id:
              item._id.toString(),

            type:
              "DEPOSIT",

            currency:
              item.currency,

            amount:
              item.amount,

            status:
              item.status,

            reference:
              item.reference,

            createdAt:
              item.createdAt
          })
        ),

        ...withdrawals.map(
          (item) => ({
            id:
              item._id.toString(),

            type:
              "WITHDRAWAL",

            currency:
              item.currency,

            amount:
              item.amount,

            status:
              item.status,

            reference:
              item.reference,

            createdAt:
              item.createdAt
          })
        )
      ];

      transactions.sort(
        (a, b) =>
          new Date(
            b.createdAt
          ) -
          new Date(
            a.createdAt
          )
      );

      return res.json({
        transactions
      });
    } catch (error) {
      console.error(
        "Transactions error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load transactions."
      });
    }
  }
);

/* =========================================================
   ADMIN STATUS
   ========================================================= */

app.get(
  "/admin/status",
  requireAdmin,
  async (req, res) => {
    return res.json({
      ok: true,

      admin: true,

      mode:
        PLATFORM_MODE,

      realFundsEnabled:
        REAL_FUNDS_ENABLED
    });
  }
);

/* =========================================================
   ADMIN USERS
   ========================================================= */

app.get(
  "/admin/users",
  requireAdmin,
  async (req, res) => {
    try {
      const users =
        await User.find({})
          .select(
            "-passwordHash"
          )
          .sort({
            createdAt: -1
          });

      return res.json({
        users
      });
    } catch (error) {
      return res.status(500).json({
        error:
          "Unable to load users."
      });
    }
  }
);

/* =========================================================
   ADMIN KYC
   ========================================================= */

app.get(
  "/admin/kyc",
  requireAdmin,
  async (req, res) => {
    try {
      const profiles =
        await KycProfile.find({})
          .sort({
            updatedAt: -1
          })
          .lean();

      const userIds =
        profiles.map(
          (item) =>
            item.userId
        );

      const users =
        await User.find({
          _id: {
            $in: userIds
          }
        })
          .select(
            "name email kycStatus"
          )
          .lean();

      const userMap =
        new Map(
          users.map(
            (user) => [
              user._id.toString(),
              user
            ]
          )
        );

      const result =
        profiles.map(
          (profile) => ({
            ...profile,

            user:
              userMap.get(
                profile.userId.toString()
              ) || null
          })
        );

      return res.json({
        kyc: result
      });
    } catch (error) {
      return res.status(500).json({
        error:
          "Unable to load KYC records."
      });
    }
  }
);

/* =========================================================
   ADMIN APPROVE KYC
   ========================================================= */

app.post(
  "/admin/kyc/:userId/approve",
  requireAdmin,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.params.userId
        );

      if (!user) {
        return res.status(404).json({
          error:
            "User not found."
        });
      }

      user.kycStatus =
        "approved";

      await user.save();

      await KycProfile.findOneAndUpdate(
        {
          userId:
            user._id
        },

        {
          status:
            "approved"
        },

        {
          upsert: true
        }
      );

      await writeAudit(
        req.user._id,
        "ADMIN_KYC_APPROVED",
        {
          targetUserId:
            user._id.toString()
        }
      );

      return res.json({
        ok: true,

        status:
          "approved"
      });
    } catch (error) {
      console.error(
        "Approve KYC error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to approve KYC."
      });
    }
  }
);

/* =========================================================
   ADMIN REJECT KYC
   ========================================================= */

app.post(
  "/admin/kyc/:userId/reject",
  requireAdmin,
  async (req, res) => {
    try {
      const user =
        await User.findById(
          req.params.userId
        );

      if (!user) {
        return res.status(404).json({
          error:
            "User not found."
        });
      }

      user.kycStatus =
        "rejected";

      await user.save();

      await KycProfile.findOneAndUpdate(
        {
          userId:
            user._id
        },

        {
          status:
            "rejected"
        },

        {
          upsert: true
        }
      );

      await writeAudit(
        req.user._id,
        "ADMIN_KYC_REJECTED",
        {
          targetUserId:
            user._id.toString()
        }
      );

      return res.json({
        ok: true,

        status:
          "rejected"
      });
    } catch (error) {
      console.error(
        "Reject KYC error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to reject KYC."
      });
    }
  }
);

/* =========================================================
   ADMIN WITHDRAWALS
   ========================================================= */

app.get(
  "/admin/withdrawals",
  requireAdmin,
  async (req, res) => {
    try {
      const withdrawals =
        await Withdrawal.find({})
          .sort({
            createdAt: -1
          })
          .limit(100)
          .lean();

      return res.json({
        withdrawals
      });
    } catch (error) {
      return res.status(500).json({
        error:
          "Unable to load withdrawals."
      });
    }
  }
);

/* =========================================================
   ADMIN APPROVE WITHDRAWAL
   ========================================================= */

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
            "Withdrawal not found."
        });
      }

      if (
        withdrawal.status !==
        "under_review"
      ) {
        return res.status(400).json({
          error:
            "Withdrawal is not awaiting review."
        });
      }

      const account =
        await Account.findOne({
          userId:
            withdrawal.userId,

          currency:
            "BTC"
        });

      if (!account) {
        return res.status(404).json({
          error:
            "BTC account not found."
        });
      }

      if (
        account.locked <
        withdrawal.amount
      ) {
        return res.status(400).json({
          error:
            "Locked balance is insufficient."
        });
      }

      account.locked -=
        withdrawal.amount;

      await account.save();

      withdrawal.status =
        "approved_sandbox";

      withdrawal.txid =
        "SANDBOX_TX_" +
        crypto.randomBytes(
          10
        ).toString("hex");

      await withdrawal.save();

      await writeAudit(
        req.user._id,
        "ADMIN_SANDBOX_WITHDRAWAL_APPROVED",
        {
          withdrawalId:
            withdrawal._id.toString()
        }
      );

      return res.json({
        ok: true,

        withdrawal,

        message:
          "Sandbox withdrawal approved. No real Bitcoin was transferred."
      });
    } catch (error) {
      console.error(
        "Approve withdrawal error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to approve withdrawal."
      });
    }
  }
);

/* =========================================================
   ADMIN REJECT WITHDRAWAL
   ========================================================= */

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
            "Withdrawal not found."
        });
      }

      if (
        withdrawal.status !==
        "under_review"
      ) {
        return res.status(400).json({
          error:
            "Withdrawal is not awaiting review."
        });
      }

      const account =
        await Account.findOne({
          userId:
            withdrawal.userId,

          currency:
            "BTC"
        });

      if (!account) {
        return res.status(404).json({
          error:
            "BTC account not found."
        });
      }

      account.locked -=
        withdrawal.amount;

      account.available +=
        withdrawal.amount;

      await account.save();

      withdrawal.status =
        "rejected";

      await withdrawal.save();

      await writeAudit(
        req.user._id,
        "ADMIN_SANDBOX_WITHDRAWAL_REJECTED",
        {
          withdrawalId:
            withdrawal._id.toString()
        }
      );

      return res.json({
        ok: true,

        withdrawal
      });
    } catch (error) {
      console.error(
        "Reject withdrawal error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to reject withdrawal."
      });
    }
  }
);

/* =========================================================
   ADMIN AUDIT
   ========================================================= */

app.get(
  "/admin/audit",
  requireAdmin,
  async (req, res) => {
    try {
      const logs =
        await AuditLog.find({})
          .sort({
            createdAt: -1
          })
          .limit(200)
          .lean();

      return res.json({
        audit: logs
      });
    } catch (error) {
      return res.status(500).json({
        error:
          "Unable to load audit log."
      });
    }
  }
);

/* =========================================================
   LOGOUT
   ========================================================= */

app.post(
  "/logout",
  async (req, res) => {
    try {
      const bearer =
        getBearerToken(req);

      if (bearer) {
        await revokeAuthToken(
          bearer
        );
      }

      if (req.session) {
        await new Promise(
          (resolve) => {
            req.session.destroy(
              () => resolve()
            );
          }
        );
      }

      res.clearCookie(
        "cityfive.sid",
        {
          httpOnly: true,
          secure: true,
          sameSite: "none"
        }
      );

      return res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        "Logout error:",
        error
      );

      return res.status(500).json({
        error:
          "Logout failed."
      });
    }
  }
);

/* =========================================================
   404
   ========================================================= */

app.use(
  (req, res) => {
    res.status(404).json({
      error:
        "Not found"
    });
  }
);

/* =========================================================
   ERROR HANDLER
   ========================================================= */

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

    if (
      res.headersSent
    ) {
      return next(error);
    }

    return res.status(500).json({
      error:
        "Internal server error"
    });
  }
);

/* =========================================================
   START SERVER
   ========================================================= */

async function startServer() {
  try {
    if (!MONGO_URI) {
      throw new Error(
        "MONGO_URI environment variable is missing."
      );
    }

    await mongoose.connect(
      MONGO_URI
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

        console.log(
          `Frontend origin: ${FRONTEND_ORIGIN}`
        );
      }
    );
  } catch (error) {
    console.error(
      "Startup failed:",
      error
    );

    process.exit(1);
  }
}

startServer();
