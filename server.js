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

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = Number(process.env.PORT) || 3000;

const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  crypto.randomBytes(32).toString("hex");

const PLATFORM_MODE =
  String(process.env.PLATFORM_MODE || "SANDBOX").toUpperCase();

/*
  IMPORTANT:
  Real customer funds remain disabled in this version.
*/
const REAL_FUNDS_ENABLED = false;

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  "https://cityfive1.github.io";

const ALLOWED_ORIGINS = [
  "https://cityfive1.github.io",
  "http://localhost:3000",
  "http://127.0.0.1:3000"
];

/* =========================================================
   APP CONFIGURATION
========================================================= */

app.set("trust proxy", 1);

/*
  CORS must allow the GitHub Pages frontend to communicate
  with the Abasthan backend while sending the session cookie.
*/
app.use(
  cors({
    origin: function (origin, callback) {
      /*
        Requests such as direct server health checks may have
        no Origin header.
      */
      if (!origin) {
        return callback(null, true);
      }

      if (
        ALLOWED_ORIGINS.includes(origin) ||
        origin === FRONTEND_ORIGIN
      ) {
        return callback(null, true);
      }

      console.warn(
        "Blocked CORS origin:",
        origin
      );

      return callback(
        new Error("CORS origin not allowed")
      );
    },

    credentials: true,

    methods: [
      "GET",
      "POST",
      "PUT",
      "PATCH",
      "DELETE",
      "OPTIONS"
    ],

    allowedHeaders: [
      "Content-Type",
      "Authorization"
    ]
  })
);

/* =========================================================
   FIREBLOCKS WEBHOOK
   MUST COME BEFORE express.json()
========================================================= */

app.post(
  "/webhooks/fireblocks",

  express.raw({
    type: "application/json",
    limit: "2mb"
  }),

  async (req, res) => {
    try {
      const signature =
        req.headers[
          "fireblocks-webhook-signature"
        ];

      const valid =
        await verifyWebhook(
          req.body,
          signature
        );

      if (!valid) {
        console.warn(
          "Rejected Fireblocks webhook: invalid signature"
        );

        return res.status(401).json({
          error:
            "Invalid webhook signature"
        });
      }

      const event =
        JSON.parse(
          Buffer
            .from(req.body)
            .toString("utf8")
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
        error:
          "Invalid webhook"
      });
    }
  }
);

/* =========================================================
   NORMAL JSON BODY
========================================================= */

app.use(
  express.json({
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

      maxAge:
        1000 *
        60 *
        60 *
        24 *
        7
    }
  })
);

/* =========================================================
   DATABASE MODELS
========================================================= */

const userSchema =
  new mongoose.Schema(
    {
      name: {
        type: String,
        required: true,
        trim: true,
        maxlength: 120
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
        enum: [
          "user",
          "admin"
        ],
        default: "user"
      },

      active: {
        type: Boolean,
        default: true
      },

      /*
        KYC status is duplicated here for fast frontend access.
        The KycProfile remains the source record.
      */
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
          "restricted",
          "suspended",
          "closed"
        ],
        default: "pending"
      },

      lastLoginAt: {
        type: Date,
        default: null
      }
    },

    {
      timestamps: true
    }
  );


const accountSchema =
  new mongoose.Schema(
    {
      userId: {
        type:
          mongoose.Schema.Types.ObjectId,

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

        default: 0,

        min: 0
      },

      locked: {
        type: Number,

        default: 0,

        min: 0
      }
    },

    {
      timestamps: true
    }
  );


const ledgerEntrySchema =
  new mongoose.Schema(
    {
      userId: {
        type:
          mongoose.Schema.Types.ObjectId,

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

        required: true,

        index: true
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


const depositSchema =
  new mongoose.Schema(
    {
      userId: {
        type:
          mongoose.Schema.Types.ObjectId,

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


const withdrawalSchema =
  new mongoose.Schema(
    {
      userId: {
        type:
          mongoose.Schema.Types.ObjectId,

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


const tradeSchema =
  new mongoose.Schema(
    {
      userId: {
        type:
          mongoose.Schema.Types.ObjectId,

        required: true
      },

      pair: {
        type: String,

        default: "BTC/CAD"
      },

      side: {
        type: String,

        enum: [
          "buy",
          "sell"
        ],

        required: true
      },

      amount: {
        type: Number,

        default: 0
      },

      price: {
        type: Number,

        default: 0
      },

      status: {
        type: String,

        default: "sandbox"
      }
    },

    {
      timestamps: true
    }
  );


const kycSchema =
  new mongoose.Schema(
    {
      userId: {
        type:
          mongoose.Schema.Types.ObjectId,

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


const auditLogSchema =
  new mongoose.Schema(
    {
      userId: {
        type:
          mongoose.Schema.Types.ObjectId,

        default: null,

        index: true
      },

      action: {
        type: String,

        required: true
      },

      details: {
        type:
          mongoose.Schema.Types.Mixed,

        default: {}
      }
    },

    {
      timestamps: true
    }
  );


const User =
  mongoose.model(
    "User",
    userSchema
  );

const Account =
  mongoose.model(
    "Account",
    accountSchema
  );

const LedgerEntry =
  mongoose.model(
    "LedgerEntry",
    ledgerEntrySchema
  );

const Deposit =
  mongoose.model(
    "Deposit",
    depositSchema
  );

const Withdrawal =
  mongoose.model(
    "Withdrawal",
    withdrawalSchema
  );

const Trade =
  mongoose.model(
    "Trade",
    tradeSchema
  );

const KycProfile =
  mongoose.model(
    "KycProfile",
    kycSchema
  );

const AuditLog =
  mongoose.model(
    "AuditLog",
    auditLogSchema
  );

/* =========================================================
   HELPERS
========================================================= */

function makeReference(prefix) {
  return (
    prefix +
    "-" +
    crypto
      .randomBytes(8)
      .toString("hex")
  ).toUpperCase();
}


function normalizeEmail(email) {
  return String(email || "")
    .trim()
    .toLowerCase();
}


function numericAmount(value) {
  const number = Number(value);

  if (
    !Number.isFinite(number) ||
    number <= 0
  ) {
    return null;
  }

  return number;
}


async function getCurrentUser(req) {

  if (!req.session.userId) {
    return null;
  }

  return User.findById(
    req.session.userId
  );
}


async function requireLogin(
  req,
  res,
  next
) {

  try {

    const user =
      await getCurrentUser(req);

    if (
      !user ||
      !user.active
    ) {

      return res.status(401).json({
        error:
          "Login required"
      });
    }

    if (
      user.accountStatus ===
      "suspended"
    ) {

      return res.status(403).json({
        error:
          "Account suspended"
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
      error:
        "Authentication error"
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

    if (
      !user ||
      !user.active ||
      user.role !== "admin"
    ) {

      return res.status(403).json({
        error:
          "Admin access required"
      });
    }

    req.user = user;

    next();

  } catch (error) {

    console.error(
      "Authorization error:",
      error.message
    );

    return res.status(500).json({
      error:
        "Authorization error"
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


async function ensureUserAccounts(
  userId
) {

  const existing =
    await Account.find({
      userId
    });

  const currencies =
    existing.map(
      account =>
        account.currency
    );

  const missing = [];

  if (
    !currencies.includes("CAD")
  ) {

    missing.push({
      userId,
      currency: "CAD",
      available: 0,
      locked: 0
    });
  }

  if (
    !currencies.includes("BTC")
  ) {

    missing.push({
      userId,
      currency: "BTC",
      available: 0,
      locked: 0
    });
  }

  if (missing.length) {
    await Account.create(
      missing
    );
  }

  return Account.find({
    userId
  });
}


/* =========================================================
   HEALTH / ROOT
========================================================= */

app.get(
  "/",
  (req, res) => {

    res.json({
      service:
        "CityFive Holdings Ltd",

      status:
        "online",

      mode:
        PLATFORM_MODE,

      realFundsEnabled:
        REAL_FUNDS_ENABLED,

      frontendOrigin:
        FRONTEND_ORIGIN
    });
  }
);


app.get(
  "/health",
  (req, res) => {

    res.json({
      status: "ok",

      mode:
        PLATFORM_MODE,

      realFundsEnabled:
        REAL_FUNDS_ENABLED
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

      const {
        name,
        email,
        password
      } = req.body || {};

      const cleanName =
        String(name || "")
          .trim();

      const normalizedEmail =
        normalizeEmail(email);

      if (
        !cleanName ||
        !normalizedEmail ||
        !password
      ) {

        return res.status(400).json({
          error:
            "Name, email and password are required"
        });
      }

      if (
        cleanName.length < 2
      ) {

        return res.status(400).json({
          error:
            "Please enter your full name"
        });
      }

      if (
        cleanName.length > 120
      ) {

        return res.status(400).json({
          error:
            "Name is too long"
        });
      }

      if (
        password.length < 8
      ) {

        return res.status(400).json({
          error:
            "Password must be at least 8 characters"
        });
      }

      const existing =
        await User.findOne({
          email:
            normalizedEmail
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
          name:
            cleanName,

          email:
            normalizedEmail,

          passwordHash,

          role:
            "user",

          active:
            true,

          kycStatus:
            "not_started",

          accountStatus:
            "pending"
        });

      await Account.create([
        {
          userId:
            user._id,

          currency:
            "CAD",

          available:
            0,

          locked:
            0
        },

        {
          userId:
            user._id,

          currency:
            "BTC",

          available:
            0,

          locked:
            0
        }
      ]);

      await KycProfile.create({
        userId:
          user._id,

        status:
          "not_started"
      });

      await writeAudit(
        user._id,
        "USER_REGISTERED"
      );

      /*
        Registration also establishes a session so the
        frontend can immediately use /me.
      */
      req.session.userId =
        user._id.toString();

      await new Promise(
        (resolve, reject) => {

          req.session.save(
            error => {

              if (error) {
                return reject(error);
              }

              resolve();
            }
          );
        }
      );

      return res.status(201).json({

        success:
          true,

        user: {
          id:
            user._id,

          name:
            user.name,

          email:
            user.email,

          role:
            user.role,

          accountStatus:
            user.accountStatus,

          kycStatus:
            user.kycStatus
        },

        mode:
          PLATFORM_MODE,

        realFundsEnabled:
          REAL_FUNDS_ENABLED
      });

    } catch (error) {

      console.error(
        "Register error:",
        error
      );

      /*
        Handles a duplicate email race safely.
      */
      if (
        error &&
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

      const {
        email,
        password
      } = req.body || {};

      const normalizedEmail =
        normalizeEmail(email);

      if (
        !normalizedEmail ||
        !password
      ) {

        return res.status(400).json({
          error:
            "Email and password are required"
        });
      }

      const user =
        await User.findOne({
          email:
            normalizedEmail
        });

      if (
        !user ||
        !user.active
      ) {

        return res.status(401).json({
          error:
            "Invalid email or password"
        });
      }

      if (
        user.accountStatus ===
        "suspended"
      ) {

        return res.status(403).json({
          error:
            "Account suspended"
        });
      }

      const valid =
        await bcrypt.compare(
          password,
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

      user.lastLoginAt =
        new Date();

      await user.save();

      await writeAudit(
        user._id,
        "USER_LOGIN"
      );

      await new Promise(
        (resolve, reject) => {

          req.session.save(
            error => {

              if (error) {
                return reject(error);
              }

              resolve();
            }
          );
        }
      );

      return res.json({

        success:
          true,

        user: {
          id:
            user._id,

          name:
            user.name,

          email:
            user.email,

          role:
            user.role,

          accountStatus:
            user.accountStatus,

          kycStatus:
            user.kycStatus
        },

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

      const accounts =
        await ensureUserAccounts(
          req.user._id
        );

      const kyc =
        await KycProfile.findOne({
          userId:
            req.user._id
        });

      const kycStatus =
        kyc
          ? kyc.status
          : (
              req.user.kycStatus ||
              "not_started"
            );

      /*
        Keep User.kycStatus synchronized.
      */
      if (
        req.user.kycStatus !==
        kycStatus
      ) {

        req.user.kycStatus =
          kycStatus;

        await req.user.save();
      }

      return res.json({

        user: {
          id:
            req.user._id,

          name:
            req.user.name,

          email:
            req.user.email,

          role:
            req.user.role,

          accountStatus:
            req.user.accountStatus,

          kycStatus:
            kycStatus
        },

        accounts,

        kyc:
          kycStatus,

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
          "Unable to load account"
      });
    }
  }
);


/* =========================================================
   KYC
========================================================= */

app.post(
  "/kyc/start",
  requireLogin,
  async (req, res) => {

    try {

      const profile =
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
            new:
              true,

            upsert:
              true
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

        success:
          true,

        status:
          profile.status,

        message:
          "Sandbox KYC workflow started. No identity documents were submitted to a real verification provider."
      });

    } catch (error) {

      console.error(
        "KYC error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to start KYC"
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
            "Live BTC deposits are not enabled"
        });
      }

      const amount =
        numericAmount(
          req.body?.amount
        );

      if (amount === null) {

        return res.status(400).json({
          error:
            "Enter a valid BTC amount"
        });
      }

      const kyc =
        await KycProfile.findOne({
          userId:
            req.user._id
        });

      if (
        !kyc ||
        kyc.status !==
          "approved"
      ) {

        return res.status(403).json({
          error:
            "KYC approval is required"
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
            "BTC account not found"
        });
      }

      const reference =
        makeReference(
          "DEMO"
        );

      const deposit =
        await Deposit.create({

          userId:
            req.user._id,

          currency:
            "BTC",

          amount:
            amount,

          status:
            "sandbox_completed",

          reference:
            reference,

          address:
            null
        });

      /*
        This is a simulated ledger credit only.
        No blockchain transaction occurs.
      */
      account.available +=
        amount;

      await account.save();

      await LedgerEntry.create({

        userId:
          req.user._id,

        currency:
          "BTC",

        type:
          "SANDBOX_DEPOSIT",

        amount:
          amount,

        reference:
          reference,

        description:
          "Simulated BTC deposit — no real Bitcoin transferred"
      });

      await writeAudit(
        req.user._id,
        "SANDBOX_BTC_DEPOSIT_CREATED",
        {
          reference,
          amount
        }
      );

      return res.status(201).json({

        success:
          true,

        mode:
          "SANDBOX",

        message:
          "Sandbox BTC deposit credited to your simulated balance. No real Bitcoin was transferred.",

        deposit
      });

    } catch (error) {

      console.error(
        "Deposit error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to create sandbox deposit"
      });
    }
  }
);


/* =========================================================
   BTC WITHDRAWAL
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
            "Live BTC withdrawals are not enabled"
        });
      }

      const amount =
        numericAmount(
          req.body?.amount
        );

      const address =
        String(
          req.body?.address || ""
        ).trim();

      if (amount === null) {

        return res.status(400).json({
          error:
            "Invalid BTC amount"
        });
      }

      if (
        address.length < 10
      ) {

        return res.status(400).json({
          error:
            "A valid sandbox BTC address is required"
        });
      }

      const kyc =
        await KycProfile.findOne({
          userId:
            req.user._id
        });

      if (
        !kyc ||
        kyc.status !==
          "approved"
      ) {

        return res.status(403).json({
          error:
            "KYC approval is required"
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
            "BTC account not found"
        });
      }

      if (
        account.available <
        amount
      ) {

        return res.status(400).json({
          error:
            "Insufficient BTC balance"
        });
      }

      const reference =
        makeReference(
          "WD"
        );

      /*
        Move the simulated amount from available to locked.
        It remains inside the sandbox until an admin approves
        the simulated withdrawal.
      */
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

          amount:
            amount,

          address:
            address,

          status:
            "under_review",

          reference:
            reference
        });

      await LedgerEntry.create({

        userId:
          req.user._id,

        currency:
          "BTC",

        type:
          "SANDBOX_WITHDRAWAL",

        amount:
          -amount,

        reference:
          reference,

        description:
          "Simulated BTC withdrawal request — no real Bitcoin sent"
      });

      await writeAudit(
        req.user._id,
        "SANDBOX_BTC_WITHDRAWAL_REQUESTED",
        {
          reference,
          amount
        }
      );

      return res.status(201).json({

        success:
          true,

        mode:
          "SANDBOX",

        message:
          "Sandbox withdrawal submitted for review. No real Bitcoin will be sent.",

        withdrawal
      });

    } catch (error) {

      console.error(
        "Withdrawal error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to create withdrawal"
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

      const accounts =
        await ensureUserAccounts(
          req.user._id
        );

      return res.json({
        accounts
      });

    } catch (error) {

      console.error(
        "Accounts error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load accounts"
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

      const [
        ledger,
        deposits,
        withdrawals,
        trades
      ] =
        await Promise.all([

          LedgerEntry.find({
            userId:
              req.user._id
          })
          .sort({
            createdAt:
              -1
          }),

          Deposit.find({
            userId:
              req.user._id
          })
          .sort({
            createdAt:
              -1
          }),

          Withdrawal.find({
            userId:
              req.user._id
          })
          .sort({
            createdAt:
              -1
          }),

          Trade.find({
            userId:
              req.user._id
          })
          .sort({
            createdAt:
              -1
          })
        ]);

      return res.json({

        ledger,

        deposits,

        withdrawals,

        trades
      });

    } catch (error) {

      console.error(
        "Transactions error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load transactions"
      });
    }
  }
);


/* =========================================================
   ADMIN — STATUS
========================================================= */

app.get(
  "/admin/status",
  requireAdmin,
  async (req, res) => {

    return res.json({

      platformMode:
        PLATFORM_MODE,

      realFundsEnabled:
        REAL_FUNDS_ENABLED,

      btcProvider:
        "disabled",

      fireblocks:
        "disabled",

      message:
        "This deployment is sandbox-only."
    });
  }
);


/* =========================================================
   ADMIN — USERS
========================================================= */

app.get(
  "/admin/users",
  requireAdmin,
  async (req, res) => {

    try {

      const users =
        await User.find()
          .select(
            "_id name email role active accountStatus kycStatus createdAt lastLoginAt"
          )
          .sort({
            createdAt:
              -1
          });

      return res.json({
        users
      });

    } catch (error) {

      console.error(
        "Admin users error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load users"
      });
    }
  }
);


/* =========================================================
   ADMIN — KYC
========================================================= */

app.get(
  "/admin/kyc",
  requireAdmin,
  async (req, res) => {

    try {

      const profiles =
        await KycProfile.find()
          .sort({
            createdAt:
              -1
          });

      return res.json({
        profiles
      });

    } catch (error) {

      console.error(
        "Admin KYC error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load KYC"
      });
    }
  }
);


/* =========================================================
   ADMIN — APPROVE KYC
========================================================= */

app.post(
  "/admin/kyc/:userId/approve",
  requireAdmin,
  async (req, res) => {

    try {

      const profile =
        await KycProfile.findOneAndUpdate(

          {
            userId:
              req.params.userId
          },

          {
            status:
              "approved"
          },

          {
            new:
              true
          }
        );

      if (!profile) {

        return res.status(404).json({
          error:
            "KYC profile not found"
        });
      }

      await User.findByIdAndUpdate(
        req.params.userId,
        {
          kycStatus:
            "approved",

          accountStatus:
            "active"
        }
      );

      await writeAudit(
        req.user._id,
        "ADMIN_KYC_APPROVED",
        {
          userId:
            req.params.userId
        }
      );

      return res.json({

        success:
          true,

        profile
      });

    } catch (error) {

      console.error(
        "Approve KYC error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to approve KYC"
      });
    }
  }
);


/* =========================================================
   ADMIN — REJECT KYC
========================================================= */

app.post(
  "/admin/kyc/:userId/reject",
  requireAdmin,
  async (req, res) => {

    try {

      const profile =
        await KycProfile.findOneAndUpdate(

          {
            userId:
              req.params.userId
          },

          {
            status:
              "rejected"
          },

          {
            new:
              true
          }
        );

      if (!profile) {

        return res.status(404).json({
          error:
            "KYC profile not found"
        });
      }

      await User.findByIdAndUpdate(
        req.params.userId,
        {
          kycStatus:
            "rejected"
        }
      );

      await writeAudit(
        req.user._id,
        "ADMIN_KYC_REJECTED",
        {
          userId:
            req.params.userId
        }
      );

      return res.json({

        success:
          true,

        profile
      });

    } catch (error) {

      console.error(
        "Reject KYC error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to reject KYC"
      });
    }
  }
);


/* =========================================================
   ADMIN — WITHDRAWALS
========================================================= */

app.get(
  "/admin/withdrawals",
  requireAdmin,
  async (req, res) => {

    try {

      const withdrawals =
        await Withdrawal.find()
          .sort({
            createdAt:
              -1
          });

      return res.json({
        withdrawals
      });

    } catch (error) {

      console.error(
        "Admin withdrawals error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load withdrawals"
      });
    }
  }
);


/* =========================================================
   ADMIN — APPROVE SANDBOX WITHDRAWAL
========================================================= */

app.post(
  "/admin/withdrawals/:id/approve",
  requireAdmin,
  async (req, res) => {

    try {

      if (
        PLATFORM_MODE !==
        "SANDBOX"
      ) {

        return res.status(403).json({
          error:
            "Live withdrawal approval is disabled"
        });
      }

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

          currency:
            "BTC"
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

      /*
        In sandbox we simply release the locked
        simulated balance. No blockchain transaction
        is created.
      */
      account.locked -=
        withdrawal.amount;

      await account.save();

      withdrawal.status =
        "approved_sandbox";

      withdrawal.txid =
        null;

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

        success:
          true,

        mode:
          "SANDBOX",

        message:
          "Sandbox withdrawal approved. No real Bitcoin was sent.",

        withdrawal
      });

    } catch (error) {

      console.error(
        "Approve withdrawal error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to approve withdrawal"
      });
    }
  }
);


/* =========================================================
   ADMIN — REJECT SANDBOX WITHDRAWAL
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

          currency:
            "BTC"
        });

      if (!account) {

        return res.status(404).json({
          error:
            "BTC account not found"
        });
      }

      /*
        Return the simulated BTC to available balance.
      */
      if (
        account.locked >=
        withdrawal.amount
      ) {

        account.locked -=
          withdrawal.amount;

        account.available +=
          withdrawal.amount;

        await account.save();
      }

      withdrawal.status =
        "rejected_sandbox";

      await withdrawal.save();

      await writeAudit(
        req.user._id,
        "ADMIN_WITHDRAWAL_REJECTED",
        {
          withdrawalId:
            withdrawal._id
        }
      );

      return res.json({

        success:
          true,

        mode:
          "SANDBOX",

        message:
          "Sandbox withdrawal rejected and simulated balance returned.",

        withdrawal
      });

    } catch (error) {

      console.error(
        "Reject withdrawal error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to reject withdrawal"
      });
    }
  }
);


/* =========================================================
   ADMIN — AUDIT LOG
========================================================= */

app.get(
  "/admin/audit",
  requireAdmin,
  async (req, res) => {

    try {

      const logs =
        await AuditLog.find()
          .sort({
            createdAt:
              -1
          })
          .limit(500);

      return res.json({
        logs
      });

    } catch (error) {

      console.error(
        "Admin audit error:",
        error
      );

      return res.status(500).json({
        error:
          "Unable to load audit logs"
      });
    }
  }
);


/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/logout",
  (req, res) => {

    req.session.destroy(
      error => {

        if (error) {

          console.error(
            "Logout error:",
            error
          );

          return res.status(500).json({
            error:
              "Logout failed"
          });
        }

        res.clearCookie(
          "cityfive.sid",
          {
            httpOnly:
              true,

            secure:
              true,

            sameSite:
              "none"
          }
        );

        return res.json({
          success:
            true
        });
      }
    );
  }
);


/* =========================================================
   404 HANDLER
========================================================= */

app.use(
  (req, res) => {

    return res.status(404).json({
      error:
        "Endpoint not found"
    });
  }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
  (
    err,
    req,
    res,
    next
  ) => {

    console.error(
      "Unhandled error:",
      err
    );

    /*
      CORS errors need a JSON response rather than
      allowing Express to return an HTML error page.
    */
    if (
      err &&
      err.message ===
        "CORS origin not allowed"
    ) {

      return res.status(403).json({
        error:
          "CORS origin not allowed"
      });
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

async function start() {

  try {

    if (
      !process.env.MONGO_URI
    ) {

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

        console.log(
          `Frontend origin: ${FRONTEND_ORIGIN}`
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


start();
