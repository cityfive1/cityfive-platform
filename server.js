  const express = require("express");
const cors = require("cors");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const cityFiveAssistant = require("./ai-free");
const OpenAI = require("openai");

const app = express();

const PORT = Number(process.env.PORT || 3000);

const MONGO_URI = process.env.MONGO_URI;
const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN || "https://cityfive1.github.io";

const SESSION_SECRET = process.env.SESSION_SECRET;

const PLATFORM_MODE =
  process.env.PLATFORM_MODE || "SANDBOX";

const REAL_FUNDS_ENABLED =
  String(process.env.REAL_FUNDS_ENABLED || "false")
    .toLowerCase() === "true";

const SANDBOX_RESET_KEY =
  process.env.SANDBOX_RESET_KEY || "";

const OPENAI_API_KEY =
  process.env.OPENAI_API_KEY || "";

/*
  IMPORTANT:
  You can optionally create OPENAI_MODEL in Abasthan.
  Example:
  OPENAI_MODEL = gpt-5-mini

  If OPENAI_MODEL is not present, this fallback is used.
*/
const OPENAI_MODEL =
  process.env.OPENAI_MODEL || "gpt-5-mini";

// --------------------------------------------------
// SAFETY: CITYFIVE IS SANDBOX ONLY
// --------------------------------------------------

if (PLATFORM_MODE !== "SANDBOX") {
  throw new Error(
    "CityFive requires PLATFORM_MODE=SANDBOX"
  );
}

if (REAL_FUNDS_ENABLED) {
  throw new Error(
    "REAL_FUNDS_ENABLED must remain false"
  );
}

if (!MONGO_URI) {
  throw new Error("MONGO_URI is missing");
}

if (!SESSION_SECRET) {
  throw new Error("SESSION_SECRET is missing");
}

// --------------------------------------------------
// MIDDLEWARE
// --------------------------------------------------

app.use(
  cors({
    origin: [
      FRONTEND_ORIGIN,
      "https://cityfive1.github.io",
      "http://localhost:3000",
      "http://localhost:5500"
    ],
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

app.use(
  express.json({
    limit: "1mb"
  })
);

// --------------------------------------------------
// HELPERS
// --------------------------------------------------

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function generateToken() {
  return crypto
    .randomBytes(32)
    .toString("hex");
}

function generateDepositReference() {
  return (
    "C5-SBX-" +
    crypto
      .randomBytes(8)
      .toString("hex")
      .toUpperCase()
  );
}

function generateWithdrawalReference() {
  return (
    "C5-WD-" +
    crypto
      .randomBytes(8)
      .toString("hex")
      .toUpperCase()
  );
}

function generateSandboxTxid() {
  return (
    "C5-TX-" +
    crypto
      .randomBytes(16)
      .toString("hex")
      .toUpperCase()
  );
}

function publicUser(user) {
  return {
    id: String(user._id),
    name: user.name,
    email: user.email,
    role: user.role,
    kycStatus: user.kycStatus,
    createdAt: user.createdAt
  };
}

function validBtcAmount(value) {
  const amount = Number(value);

  if (!Number.isFinite(amount)) {
    return null;
  }

  if (amount <= 0) {
    return null;
  }

  if (amount > 100) {
    return null;
  }

  return Number(amount.toFixed(8));
}

async function audit(
  userId,
  action,
  details = {}
) {
  try {
    await Audit.create({
      user: userId || null,
      action,
      details
    });
  } catch (error) {
    console.error(
      "Audit error:",
      error.message
    );
  }
}

async function issueToken(user) {
  const rawToken = generateToken();

  await AuthToken.create({
    user: user._id,
    tokenHash: sha256(rawToken),
    expiresAt: new Date(
      Date.now() +
        1000 * 60 * 60 * 24 * 7
    )
  });

  return rawToken;
}

function getBearerToken(req) {
  const header =
    req.headers.authorization || "";

  if (!header.startsWith("Bearer ")) {
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
      getBearerToken(req);

    if (!token) {
      return res.status(401).json({
        error: "Authentication required"
      });
    }

    const tokenDoc =
      await AuthToken.findOne({
        tokenHash: sha256(token),
        expiresAt: {
          $gt: new Date()
        }
      }).populate("user");

    if (
      !tokenDoc ||
      !tokenDoc.user
    ) {
      return res.status(401).json({
        error: "Invalid or expired session"
      });
    }

    req.user =
      tokenDoc.user;

    req.authToken =
      tokenDoc;

    next();
  } catch (error) {
    console.error(
      "Authentication error:",
      error
    );

    return res.status(401).json({
      error: "Authentication failed"
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
        req.user.role !== "admin"
      ) {
        return res
          .status(403)
          .json({
            error:
              "Administrator access required"
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
      user: userId
    });

  if (!account) {
    account =
      await Account.create({
        user: userId,
        cadBalance: 0,
        btcBalance: 0,
        pendingBtcBalance: 0
      });
  }

  return account;
}

// --------------------------------------------------
// DATABASE MODELS
// --------------------------------------------------

const UserSchema =
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
        enum: [
          "user",
          "admin"
        ],
        default: "user"
      },

      kycStatus: {
        type: String,
        enum: [
          "pending",
          "submitted",
          "approved",
          "rejected"
        ],
        default: "pending"
      }
    },
    {
      timestamps: true
    }
  );

const User =
  mongoose.model(
    "User",
    UserSchema
  );

const AuthTokenSchema =
  new mongoose.Schema(
    {
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
      },

      tokenHash: {
        type: String,
        required: true,
        unique: true
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
    AuthTokenSchema
  );

const PasswordResetSchema =
  new mongoose.Schema(
    {
      user: {
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
    PasswordResetSchema
  );

const AccountSchema =
  new mongoose.Schema(
    {
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
        unique: true
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
    AccountSchema
  );

// --------------------------------------------------
// DEPOSITS
// --------------------------------------------------

const DepositSchema =
  new mongoose.Schema(
    {
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
      },

      amount: {
        type: Number,
        required: true
      },

      currency: {
        type: String,
        default: "BTC"
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

      /*
        IMPORTANT:
        Every new deposit gets a unique reference.
        This fixes the previous MongoDB:
        duplicate key error reference_1.
      */
      reference: {
        type: String,
        required: true,
        unique: true,
        index: true
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

const Deposit =
  mongoose.model(
    "Deposit",
    DepositSchema
  );

// --------------------------------------------------
// WITHDRAWALS
// --------------------------------------------------

const WithdrawalSchema =
  new mongoose.Schema(
    {
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true
      },

      amount: {
        type: Number,
        required: true
      },

      currency: {
        type: String,
        default: "BTC"
      },

      destination: {
        type: String,
        required: true
      },

      status: {
        type: String,
        enum: [
          "pending",
          "approved",
          "rejected"
        ],
        default: "pending"
      },

      reference: {
        type: String,
        required: true,
        unique: true,
        index: true
      },

      note: {
        type: String,
        default: ""
      }
    },
    {
      timestamps: true
    }
  );

const Withdrawal =
  mongoose.model(
    "Withdrawal",
    WithdrawalSchema
  );

// --------------------------------------------------
// LEDGER
// --------------------------------------------------

const LedgerSchema =
  new mongoose.Schema(
    {
      user: {
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

      reference: {
        type: String,
        default: ""
      }
    },
    {
      timestamps: true
    }
  );

const Ledger =
  mongoose.model(
    "Ledger",
    LedgerSchema
  );

// --------------------------------------------------
// KYC
// --------------------------------------------------

const KycProfileSchema =
  new mongoose.Schema(
    {
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
        required: true,
        unique: true
      },

      legalName: {
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
      },

      documentNumber: {
        type: String,
        default: ""
      },

      status: {
        type: String,
        enum: [
          "submitted",
          "approved",
          "rejected"
        ],
        default: "submitted"
      }
    },
    {
      timestamps: true
    }
  );

const KycProfile =
  mongoose.model(
    "KycProfile",
    KycProfileSchema
  );

// --------------------------------------------------
// AUDIT
// --------------------------------------------------

const AuditSchema =
  new mongoose.Schema(
    {
      user: {
        type: mongoose.Schema.Types.ObjectId,
        ref: "User",
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

const Audit =
  mongoose.model(
    "Audit",
    AuditSchema
  );

// --------------------------------------------------
// OPENAI
// --------------------------------------------------

let openai = null;

if (OPENAI_API_KEY) {
  openai = new OpenAI({
    apiKey: OPENAI_API_KEY
  });
}

// --------------------------------------------------
// PUBLIC
// --------------------------------------------------

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
      ok: true,

      service:
        "CityFive Holdings Ltd",

      mode: "SANDBOX",

      realFundsEnabled: false,

      database:
        mongoose.connection
          .readyState === 1
          ? "connected"
          : "disconnected"
    });
  }
);

// --------------------------------------------------
// REGISTER
// --------------------------------------------------

app.post(
  "/register",
  async (req, res) => {
    try {
      const name =
        String(
          req.body.name || ""
        ).trim();

      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );

      if (
        !name ||
        !email ||
        !password
      ) {
        return res
          .status(400)
          .json({
            error:
              "Name, email and password are required"
          });
      }

      if (
        password.length < 8
      ) {
        return res
          .status(400)
          .json({
            error:
              "Password must be at least 8 characters"
          });
      }

      const existing =
        await User.findOne({
          email
        });

      if (existing) {
        return res
          .status(409)
          .json({
            error:
              "An account with this email already exists"
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
          kycStatus: "pending"
        });

      await ensureAccounts(
        user._id
      );

      await audit(
        user._id,
        "USER_REGISTERED"
      );

      const token =
        await issueToken(user);

      res.status(201).json({
        token,
        user:
          publicUser(user)
      });
    } catch (error) {
      console.error(
        "Register error:",
        error
      );

      res.status(500).json({
        error:
          "Could not create account"
      });
    }
  }
);

// --------------------------------------------------
// LOGIN
// --------------------------------------------------

app.post(
  "/login",
  async (req, res) => {
    try {
      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      const password =
        String(
          req.body.password || ""
        );

      const user =
        await User.findOne({
          email
        });

      if (!user) {
        return res
          .status(401)
          .json({
            error:
              "Invalid email or password"
          });
      }

      const valid =
        await bcrypt.compare(
          password,
          user.passwordHash
        );

      if (!valid) {
        return res
          .status(401)
          .json({
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
        user._id,
        "USER_LOGIN"
      );

      res.json({
        token,
        user:
          publicUser(user)
      });
    } catch (error) {
      console.error(
        "Login error:",
        error
      );

      res.status(500).json({
        error: "Login failed"
      });
    }
  }
);

// --------------------------------------------------
// ME
// --------------------------------------------------

app.get(
  "/me",
  requireAuth,
  async (req, res) => {
    res.json({
      user:
        publicUser(req.user)
    });
  }
);

// --------------------------------------------------
// SANDBOX PASSWORD RESET
// --------------------------------------------------

app.post(
  "/sandbox/request-password-reset",
  async (req, res) => {
    try {
      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      const user =
        await User.findOne({
          email
        });

      if (!user) {
        return res.json({
          ok: true,

          message:
            "If the account exists, a sandbox reset token was created."
        });
      }

      const rawToken =
        crypto
          .randomBytes(24)
          .toString("hex");

      await PasswordReset.create({
        user: user._id,

        tokenHash:
          sha256(rawToken),

        expiresAt:
          new Date(
            Date.now() +
              15 * 60 * 1000
          )
      });

      res.json({
        ok: true,

        message:
          "Sandbox password reset token created.",

        resetToken:
          rawToken
      });
    } catch (error) {
      console.error(
        "Password reset request error:",
        error
      );

      res.status(500).json({
        error:
          "Could not create reset request"
      });
    }
  }
);

app.post(
  "/sandbox/reset-password",
  async (req, res) => {
    try {
      const token =
        String(
          req.body.token || ""
        );

      const newPassword =
        String(
          req.body.newPassword || ""
        );

      if (
        !token ||
        !newPassword
      ) {
        return res
          .status(400)
          .json({
            error:
              "Token and new password are required"
          });
      }

      if (
        newPassword.length < 8
      ) {
        return res
          .status(400)
          .json({
            error:
              "Password must be at least 8 characters"
          });
      }

      const reset =
        await PasswordReset.findOne(
          {
            tokenHash:
              sha256(token),

            expiresAt: {
              $gt: new Date()
            }
          }
        );

      if (!reset) {
        return res
          .status(400)
          .json({
            error:
              "Invalid or expired reset token"
          });
      }

      const passwordHash =
        await bcrypt.hash(
          newPassword,
          12
        );

      await User.findByIdAndUpdate(
        reset.user,
        {
          passwordHash
        }
      );

      await PasswordReset.deleteMany(
        {
          user: reset.user
        }
      );

      res.json({
        ok: true,

        message:
          "Password changed successfully."
      });
    } catch (error) {
      console.error(
        "Password reset error:",
        error
      );

      res.status(500).json({
        error:
          "Could not reset password"
      });
    }
  }
);

// --------------------------------------------------
// KYC GET
// --------------------------------------------------

app.get(
  "/kyc",
  requireAuth,
  async (req, res) => {
    try {
      const profile =
        await KycProfile.findOne({
          user: req.user._id
        });

      res.json({
        status:
          req.user.kycStatus,

        profile:
          profile || null
      });
    } catch (error) {
      console.error(
        "KYC get error:",
        error
      );

      res.status(500).json({
        error:
          "Could not load KYC"
      });
    }
  }
);

// --------------------------------------------------
// KYC SUBMIT
// --------------------------------------------------

app.post(
  "/kyc",
  requireAuth,
  async (req, res) => {
    try {
      const legalName =
        String(
          req.body.legalName ||
            req.user.name ||
            ""
        ).trim();

      const country =
        String(
          req.body.country || ""
        ).trim();

      const documentType =
        String(
          req.body.documentType ||
            ""
        ).trim();

      const documentNumber =
        String(
          req.body.documentNumber ||
            ""
        ).trim();

      if (
        !legalName ||
        !country ||
        !documentType
      ) {
        return res
          .status(400)
          .json({
            error:
              "Legal name, country and document type are required"
          });
      }

      let profile =
        await KycProfile.findOne({
          user: req.user._id
        });

      if (!profile) {
        profile =
          await KycProfile.create({
            user: req.user._id,
            legalName,
            country,
            documentType,
            documentNumber,
            status: "submitted"
          });
      } else {
        profile.legalName =
          legalName;

        profile.country =
          country;

        profile.documentType =
          documentType;

        profile.documentNumber =
          documentNumber;

        profile.status =
          "submitted";

        await profile.save();
      }

      req.user.kycStatus =
        "submitted";

      await req.user.save();

      await audit(
        req.user._id,
        "KYC_SUBMITTED"
      );

      res.json({
        ok: true,

        message:
          "Sandbox verification submitted successfully.",

        status: "submitted",

        profile
      });
    } catch (error) {
      console.error(
        "KYC submit error:",
        error
      );

      res.status(500).json({
        error:
          "Could not submit verification"
      });
    }
  }
);

// --------------------------------------------------
// KYC SUBMIT ALIAS
// --------------------------------------------------

app.post(
  "/kyc/submit",
  requireAuth,
  async (req, res) => {
    try {
      const legalName =
        String(
          req.body.legalName ||
            req.user.name ||
            ""
        ).trim();

      const country =
        String(
          req.body.country ||
            "Canada"
        ).trim();

      const documentType =
        String(
          req.body.documentType ||
            "Government ID"
        ).trim();

      const documentNumber =
        String(
          req.body.documentNumber ||
            ""
        ).trim();

      let profile =
        await KycProfile.findOne({
          user: req.user._id
        });

      if (!profile) {
        profile =
          await KycProfile.create({
            user: req.user._id,
            legalName,
            country,
            documentType,
            documentNumber,
            status: "submitted"
          });
      } else {
        profile.legalName =
          legalName;

        profile.country =
          country;

        profile.documentType =
          documentType;

        profile.documentNumber =
          documentNumber;

        profile.status =
          "submitted";

        await profile.save();
      }

      req.user.kycStatus =
        "submitted";

      await req.user.save();

      await audit(
        req.user._id,
        "KYC_SUBMITTED"
      );

      res.json({
        ok: true,

        message:
          "Sandbox verification submitted successfully.",

        status: "submitted",

        profile
      });
    } catch (error) {
      console.error(
        "KYC submit error:",
        error
      );

      res.status(500).json({
        error:
          "Could not submit verification"
      });
    }
  }
);

// --------------------------------------------------
// ACCOUNTS
// --------------------------------------------------

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
              account.pendingBtcBalance ||
                0
            ),

          currency: "CAD"
        }
      });
    } catch (error) {
      console.error(
        "Accounts error:",
        error
      );

      res.status(500).json({
        error:
          "Could not load account"
      });
    }
  }
);

// --------------------------------------------------
// CREATE SANDBOX BTC DEPOSIT
// --------------------------------------------------

app.post(
  "/deposits/btc",
  requireAuth,
  async (req, res) => {
    try {
      const amount =
        validBtcAmount(
          req.body.amount
        );

      if (!amount) {
        return res
          .status(400)
          .json({
            error:
              "Enter a valid BTC amount"
          });
      }

      const reference =
        generateDepositReference();

      const deposit =
        await Deposit.create({
          user: req.user._id,

          amount,

          currency: "BTC",

          status: "pending",

          reference
        });

      const account =
        await ensureAccounts(
          req.user._id
        );

      account.pendingBtcBalance =
        Number(
          account.pendingBtcBalance ||
            0
        ) + amount;

      await account.save();

      await Ledger.create({
        user: req.user._id,

        type:
          "deposit_pending",

        currency: "BTC",

        amount,

        description:
          "Sandbox BTC deposit created",

        reference
      });

      await audit(
        req.user._id,
        "SANDBOX_BTC_DEPOSIT_CREATED",
        {
          amount,
          reference
        }
      );

      res.status(201).json({
        ok: true,

        message:
          "Simulated BTC deposit created. No Bitcoin was transferred.",

        deposit: {
          id: String(
            deposit._id
          ),

          amount:
            deposit.amount,

          currency:
            deposit.currency,

          status:
            deposit.status,

          reference:
            deposit.reference,

          txid:
            deposit.txid
        }
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

// --------------------------------------------------
// CONFIRM SANDBOX BTC DEPOSIT
// --------------------------------------------------

app.post(
  "/deposits/btc/:id/confirm",
  requireAuth,
  async (req, res) => {
    try {
      const deposit =
        await Deposit.findOne({
          _id: req.params.id,

          user: req.user._id
        });

      if (!deposit) {
        return res
          .status(404)
          .json({
            error:
              "Deposit not found"
          });
      }

      if (
        deposit.status ===
        "confirmed"
      ) {
        return res.json({
          ok: true,

          message:
            "Deposit is already confirmed.",

          deposit
        });
      }

      const account =
        await ensureAccounts(
          req.user._id
        );

      account.pendingBtcBalance =
        Math.max(
          0,

          Number(
            account.pendingBtcBalance ||
              0
          ) -
            Number(
              deposit.amount || 0
            )
        );

      account.btcBalance =
        Number(
          account.btcBalance || 0
        ) +
        Number(
          deposit.amount || 0
        );

      await account.save();

      deposit.status =
        "confirmed";

      deposit.txid =
        generateSandboxTxid();

      await deposit.save();

      await Ledger.create({
        user: req.user._id,

        type:
          "deposit_confirmed",

        currency: "BTC",

        amount:
          deposit.amount,

        description:
          "Sandbox BTC deposit confirmed",

        reference:
          deposit.reference
      });

      await audit(
        req.user._id,
        "SANDBOX_BTC_DEPOSIT_CONFIRMED",
        {
          amount:
            deposit.amount,

          reference:
            deposit.reference,

          txid:
            deposit.txid
        }
      );

      res.json({
        ok: true,

        message:
          "Simulated BTC deposit confirmed. No blockchain transaction occurred.",

        deposit
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

// --------------------------------------------------
// DEPOSIT HISTORY
// --------------------------------------------------

app.get(
  "/deposits",
  requireAuth,
  async (req, res) => {
    try {
      const deposits =
        await Deposit.find({
          user: req.user._id
        }).sort({
          createdAt: -1
        });

      res.json({
        deposits
      });
    } catch (error) {
      console.error(
        "Deposit history error:",
        error
      );

      res.status(500).json({
        error:
          "Could not load deposits"
      });
    }
  }
);

// --------------------------------------------------
// CREATE SANDBOX WITHDRAWAL
// --------------------------------------------------

app.post(
  "/withdrawals/btc",
  requireAuth,
  async (req, res) => {
    try {
      const amount =
        validBtcAmount(
          req.body.amount
        );

      const destination =
        String(
          req.body.destination ||
            "Sandbox destination"
        ).trim();

      if (!amount) {
        return res
          .status(400)
          .json({
            error:
              "Enter a valid BTC amount"
          });
      }

      if (!destination) {
        return res
          .status(400)
          .json({
            error:
              "Destination is required"
          });
      }

      const account =
        await ensureAccounts(
          req.user._id
        );

      if (
        Number(
          account.btcBalance || 0
        ) < amount
      ) {
        return res
          .status(400)
          .json({
            error:
              "Insufficient simulated BTC balance"
          });
      }

      account.btcBalance =
        Number(
          account.btcBalance || 0
        ) - amount;

      await account.save();

      const reference =
        generateWithdrawalReference();

      const withdrawal =
        await Withdrawal.create({
          user: req.user._id,

          amount,

          currency: "BTC",

          destination,

          status: "pending",

          reference,

          note:
            "Sandbox withdrawal awaiting administrator review"
        });

      await Ledger.create({
        user: req.user._id,

        type:
          "withdrawal_pending",

        currency: "BTC",

        amount: -amount,

        description:
          "Sandbox BTC withdrawal requested",

        reference
      });

      await audit(
        req.user._id,
        "SANDBOX_BTC_WITHDRAWAL_CREATED",
        {
          amount,
          reference
        }
      );

      res.status(201).json({
        ok: true,

        message:
          "Simulated withdrawal submitted for sandbox review. No Bitcoin was sent.",

        withdrawal
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

// --------------------------------------------------
// WITHDRAWAL HISTORY
// --------------------------------------------------

app.get(
  "/withdrawals",
  requireAuth,
  async (req, res) => {
    try {
      const withdrawals =
        await Withdrawal.find({
          user: req.user._id
        }).sort({
          createdAt: -1
        });

      res.json({
        withdrawals
      });
    } catch (error) {
      console.error(
        "Withdrawal history error:",
        error
      );

      res.status(500).json({
        error:
          "Could not load withdrawals"
      });
    }
  }
);

// --------------------------------------------------
// TRANSACTIONS
// --------------------------------------------------

app.get(
  "/transactions",
  requireAuth,
  async (req, res) => {
    try {
      const transactions =
        await Ledger.find({
          user: req.user._id
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

// --------------------------------------------------
// LOGOUT
// --------------------------------------------------

app.post(
  "/logout",
  requireAuth,
  async (req, res) => {
    try {
      await AuthToken.deleteOne({
        _id:
          req.authToken._id
      });

      res.json({
        ok: true
      });
    } catch (error) {
      console.error(
        "Logout error:",
        error
      );

      res.status(500).json({
        error:
          "Could not log out"
      });
    }
  }
);

// --------------------------------------------------
// ADMIN USERS
// --------------------------------------------------

app.get(
  "/admin/users",
  requireAdmin,
  async (req, res) => {
    try {
      const users =
        await User.find()
          .select(
            "-passwordHash"
          )
          .sort({
            createdAt: -1
          });

      res.json({
        users
      });
    } catch (error) {
      console.error(
        "Admin users error:",
        error
      );

      res.status(500).json({
        error:
          "Could not load users"
      });
    }
  }
);

// --------------------------------------------------
// ADMIN WITHDRAWALS
// --------------------------------------------------

app.get(
  "/admin/withdrawals",
  requireAdmin,
  async (req, res) => {
    try {
      const withdrawals =
        await Withdrawal.find()
          .populate(
            "user",
            "name email"
          )
          .sort({
            createdAt: -1
          });

      res.json({
        withdrawals
      });
    } catch (error) {
      console.error(
        "Admin withdrawals error:",
        error
      );

      res.status(500).json({
        error:
          "Could not load withdrawals"
      });
    }
  }
);

// --------------------------------------------------
// ADMIN REJECT WITHDRAWAL
// --------------------------------------------------

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
        return res
          .status(404)
          .json({
            error:
              "Withdrawal not found"
          });
      }

      if (
        withdrawal.status !==
        "pending"
      ) {
        return res
          .status(400)
          .json({
            error:
              "Withdrawal is no longer pending"
          });
      }

      const account =
        await ensureAccounts(
          withdrawal.user
        );

      account.btcBalance =
        Number(
          account.btcBalance || 0
        ) +
        Number(
          withdrawal.amount || 0
        );

      await account.save();

      withdrawal.status =
        "rejected";

      withdrawal.note =
        "Sandbox withdrawal rejected by administrator.";

      await withdrawal.save();

      await Ledger.create({
        user:
          withdrawal.user,

        type:
          "withdrawal_reversed",

        currency: "BTC",

        amount:
          withdrawal.amount,

        description:
          "Sandbox withdrawal rejected and balance restored",

        reference:
          withdrawal.reference
      });

      await audit(
        req.user._id,
        "ADMIN_REJECTED_WITHDRAWAL",
        {
          withdrawalId:
            String(
              withdrawal._id
            ),

          reference:
            withdrawal.reference
        }
      );

      res.json({
        ok: true,

        withdrawal
      });
    } catch (error) {
      console.error(
        "Admin reject withdrawal error:",
        error
      );

      res.status(500).json({
        error:
          "Could not reject withdrawal"
      });
    }
  }
);

// --------------------------------------------------
// --------------------------------------------------
// CITYFIVE AI — FREE SANDBOX ASSISTANT
// --------------------------------------------------

app.post(
  "/ai/chat",
  requireAuth,
  async (req, res) => {
    try {
      const message = String(req.body.message || "").trim();

      if (!message) {
        return res.status(400).json({
          error: "Message is required"
        });
      }

      const reply = await cityFiveAssistant(
        message,
        req.user,
        Account
      );

      res.json({ reply });
    } catch (error) {
      console.error("CityFive sandbox assistant error:", error);

      res.status(500).json({
        error: "CityFive assistant could not complete the request."
      });
    }
  }
);

// ERROR HANDLER
// --------------------------------------------------

app.use(
  (
    err,
    req,
    res,
    next
  ) => {
    console.error(
      "Unhandled server error:",
      err
    );

    res.status(500).json({
      error:
        "Internal server error"
    });
  }
);

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(
  PORT,
  "0.0.0.0",
  () => {
    console.log(
      `Server listening on port ${PORT}`
    );

    console.log(
      "Platform mode: SANDBOX"
    );

    console.log(
      "Real funds enabled: false"
    );

    console.log(
      `OpenAI API key configured: ${
        OPENAI_API_KEY
          ? "yes"
          : "no"
      }`
    );

    console.log(
      `OpenAI model: ${OPENAI_MODEL}`
    );
  }
);

// --------------------------------------------------
// MONGODB
// --------------------------------------------------

mongoose
  .connect(MONGO_URI)
  .then(() => {
    console.log(
      "DB connected"
    );
  })
  .catch((error) => {
    console.error(
      "DB connection error:",
      error.message
    );
  });

// --------------------------------------------------
// SHUTDOWN
// --------------------------------------------------

process.on(
  "SIGTERM",
  async () => {
    console.log(
      "SIGTERM received. Shutting down."
    );

    try {
      await mongoose
        .connection
        .close();
    } catch (error) {
      console.error(
        "Mongo shutdown error:",
        error.message
      );
    }

    process.exit(0);
  }
);

process.on(
  "SIGINT",
  async () => {
    console.log(
      "SIGINT received. Shutting down."
    );

    try {
      await mongoose
        .connection
        .close();
    } catch (error) {
      console.error(
        "Mongo shutdown error:",
        error.message
      );
    }

    process.exit(0);
  }
);
