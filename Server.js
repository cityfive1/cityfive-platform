"use strict";

// CityFive Holdings Ltd
// Phase 1 — SANDBOX ONLY
// No real BTC is moved or held by this application.

const express = require("express");
const mongoose = require("mongoose");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const OpenAI = require("openai");

const app = express();

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = Number(process.env.PORT || 3000);

const MONGO_URI =
  process.env.MONGO_URI || "";

const FRONTEND_ORIGIN =
  process.env.FRONTEND_ORIGIN ||
  "https://cityfive1.github.io";

const SESSION_SECRET =
  process.env.SESSION_SECRET || "";

const PLATFORM_MODE = String(
  process.env.PLATFORM_MODE || "SANDBOX"
).toUpperCase();

const REAL_FUNDS_ENABLED =
  process.env.REAL_FUNDS_ENABLED === "true";

const IS_SANDBOX =
  PLATFORM_MODE === "SANDBOX" &&
  !REAL_FUNDS_ENABLED;

const SANDBOX_RESET_KEY =
  process.env.SANDBOX_RESET_KEY || "";

const OPENAI_API_KEY =
  process.env.OPENAI_API_KEY || "";

const OPENAI_MODEL =
  process.env.OPENAI_MODEL || "gpt-5.5";

/* =========================================================
   SAFETY CHECKS
========================================================= */

if (!MONGO_URI || !SESSION_SECRET) {
  console.error(
    "MONGO_URI and SESSION_SECRET are required."
  );

  process.exit(1);
}

if (!IS_SANDBOX) {
  console.error(
    "Phase 1 build is sandbox-only. " +
      "Set PLATFORM_MODE=SANDBOX and " +
      "REAL_FUNDS_ENABLED=false."
  );

  process.exit(1);
}

/* =========================================================
   CORS
========================================================= */

const allowedOrigins = new Set([
  FRONTEND_ORIGIN,
  "https://cityfive1.github.io",
  "http://localhost:3000",
  "http://127.0.0.1:3000"
]);

app.set("trust proxy", 1);

app.use(
  cors({
    origin(origin, callback) {
      if (
        !origin ||
        allowedOrigins.has(origin)
      ) {
        return callback(null, true);
      }

      return callback(
        new Error(
          "CORS origin not allowed"
        )
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

app.use(
  express.json({
    limit: "1mb"
  })
);

/* =========================================================
   DATABASE MODELS
========================================================= */

/* ---------- User ---------- */

const UserSchema =
  new mongoose.Schema(
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
        enum: [
          "user",
          "admin"
        ],
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
        default: "active"
      },

      active: {
        type: Boolean,
        default: true
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

const User =
  mongoose.model(
    "User",
    UserSchema
  );

/* ---------- Authentication Token ---------- */

const AuthTokenSchema =
  new mongoose.Schema(
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

const AuthToken =
  mongoose.model(
    "AuthToken",
    AuthTokenSchema
  );

/* ---------- Password Reset ---------- */

const PasswordResetSchema =
  new mongoose.Schema(
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
      },

      usedAt: {
        type: Date,
        default: null
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

/* ---------- Account ---------- */

const AccountSchema =
  new mongoose.Schema(
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

      balance: {
        type: Number,
        default: 0,
        min: 0
      }
    },
    {
      timestamps: true
    }
  );

AccountSchema.index(
  {
    userId: 1,
    currency: 1
  },
  {
    unique: true
  }
);

const Account =
  mongoose.model(
    "Account",
    AccountSchema
  );

/* ---------- Deposit ---------- */

const DepositSchema =
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        index: true
      },

      asset: {
        type: String,
        default: "BTC"
      },

      amount: {
        type: Number,
        required: true
      },

      address: {
        type: String,
        default: null
      },

      txid: {
        type: String,
        default: null,
        index: true
      },

      status: {
        type: String,
        enum: [
          "pending",
          "confirmed",
          "rejected"
        ],
        default: "pending"
      },

      mode: {
        type: String,
        default: "SANDBOX"
      },

      confirmations: {
        type: Number,
        default: 0
      },

      requiredConfirmations: {
        type: Number,
        default: 3
      },

      creditApplied: {
        type: Boolean,
        default: false
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

/* ---------- Withdrawal ---------- */

const WithdrawalSchema =
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        required: true,
        index: true
      },

      asset: {
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

      txid: {
        type: String,
        default: null
      },

      status: {
        type: String,
        enum: [
          "pending",
          "approved",
          "rejected",
          "submitted",
          "completed"
        ],
        default: "pending"
      },

      mode: {
        type: String,
        default: "SANDBOX"
      },

      rejectionReason: {
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

/* ---------- Ledger ---------- */

const LedgerSchema =
  new mongoose.Schema(
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
          "deposit",
          "withdrawal",
          "adjustment",
          "withdrawal_refund"
        ],
        required: true
      },

      amount: {
        type: Number,
        required: true
      },

      referenceId: {
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

LedgerSchema.index(
  {
    type: 1,
    referenceId: 1
  },
  {
    unique: true
  }
);

const Ledger =
  mongoose.model(
    "Ledger",
    LedgerSchema
  );

/* ---------- KYC ---------- */

const KycProfileSchema =
  new mongoose.Schema(
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
      },

      submittedAt: {
        type: Date,
        default: null
      },

      reviewedAt: {
        type: Date,
        default: null
      },

      reviewNote: {
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
    KycProfileSchema
  );

/* ---------- Audit ---------- */

const AuditSchema =
  new mongoose.Schema(
    {
      userId: {
        type: mongoose.Schema.Types.ObjectId,
        default: null,
        index: true
      },

      actorId: {
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
      },

      ip: {
        type: String,
        default: ""
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

/* =========================================================
   HELPERS
========================================================= */

const sha256 = (value) =>
  crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");

function publicUser(user) {
  return {
    id: String(user._id),
    name: user.name,
    email: user.email,
    role: user.role,
    kycStatus: user.kycStatus,
    accountStatus:
      user.accountStatus,
    active: user.active
  };
}

async function audit(data) {
  try {
    await Audit.create(data);
  } catch (error) {
    console.error(
      "Audit error:",
      error.message
    );
  }
}

async function issueToken(userId) {
  const rawToken =
    crypto
      .randomBytes(48)
      .toString("hex");

  await AuthToken.create({
    tokenHash:
      sha256(rawToken),

    userId,

    expiresAt:
      new Date(
        Date.now() +
          7 *
            24 *
            60 *
            60 *
            1000
      )
  });

  return rawToken;
}

function bearer(req) {
  const value =
    req.headers.authorization || "";

  if (
    !value.startsWith(
      "Bearer "
    )
  ) {
    return "";
  }

  return value
    .slice(7)
    .trim();
}

async function requireAuth(
  req,
  res,
  next
) {
  try {
    const rawToken =
      bearer(req);

    if (!rawToken) {
      return res
        .status(401)
        .json({
          ok: false,
          error:
            "Authentication required."
        });
    }

    const token =
      await AuthToken.findOne({
        tokenHash:
          sha256(rawToken),

        expiresAt: {
          $gt: new Date()
        }
      });

    if (!token) {
      return res
        .status(401)
        .json({
          ok: false,
          error:
            "Invalid or expired session."
        });
    }

    const user =
      await User.findById(
        token.userId
      );

    if (
      !user ||
      !user.active ||
      user.accountStatus ===
        "suspended"
    ) {
      return res
        .status(403)
        .json({
          ok: false,
          error:
            "Account unavailable."
        });
    }

    req.user = user;
    req.authToken = token;

    next();
  } catch (error) {
    next(error);
  }
}

function requireAdmin(
  req,
  res,
  next
) {
  if (
    !req.user ||
    req.user.role !== "admin"
  ) {
    return res
      .status(403)
      .json({
        ok: false,
        error:
          "Admin access required."
      });
  }

  next();
}

async function ensureAccounts(
  userId,
  session = null
) {
  for (
    const currency of [
      "CAD",
      "USD",
      "BTC"
    ]
  ) {
    const options = {
      upsert: true
    };

    if (session) {
      options.session = session;
    }

    await Account.updateOne(
      {
        userId,
        currency
      },
      {
        $setOnInsert: {
          userId,
          currency,
          balance: 0
        }
      },
      options
    );
  }
}

function validBtcAmount(
  value
) {
  const amount =
    Number(value);

  return (
    Number.isFinite(amount) &&
    amount > 0 &&
    amount <= 100
  );
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

      mode: "SANDBOX",

      realFundsEnabled: false,

      phase: 1,

      message:
        "Sandbox build. No real BTC is moved."
    });
  }
);

app.get(
  "/health",
  (req, res) => {
    res.json({
      ok: true,
      mode: "SANDBOX",
      realFundsEnabled: false
    });
  }
);

/* =========================================================
   AUTHENTICATION
========================================================= */

/* ---------- Register ---------- */

app.post(
  "/register",
  async (req, res, next) => {
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
        password.length < 10
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Name, valid email and a password of at least 10 characters are required."
          });
      }

      const existingUser =
        await User.findOne({
          email
        });

      if (existingUser) {
        return res
          .status(409)
          .json({
            ok: false,
            error:
              "Email already registered."
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
          role: "user"
        });

      await ensureAccounts(
        user._id
      );

      await audit({
        userId:
          user._id,

        actorId:
          user._id,

        action:
          "USER_REGISTERED",

        ip:
          req.ip
      });

      const token =
        await issueToken(
          user._id
        );

      res
        .status(201)
        .json({
          ok: true,
          token,
          user:
            publicUser(user),
          mode: "SANDBOX",
          realFundsEnabled:
            false
        });
    } catch (error) {
      next(error);
    }
  }
);

/* ---------- Login ---------- */

app.post(
  "/login",
  async (req, res, next) => {
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

      if (
        !user ||
        !(await bcrypt.compare(
          password,
          user.passwordHash
        ))
      ) {
        return res
          .status(401)
          .json({
            ok: false,
            error:
              "Invalid email or password."
          });
      }

      if (
        !user.active ||
        user.accountStatus ===
          "suspended"
      ) {
        return res
          .status(403)
          .json({
            ok: false,
            error:
              "Account unavailable."
          });
      }

      user.lastLoginAt =
        new Date();

      await user.save();

      await ensureAccounts(
        user._id
      );

      const token =
        await issueToken(
          user._id
        );

      res.json({
        ok: true,
        token,
        user:
          publicUser(user),
        mode: "SANDBOX",
        realFundsEnabled:
          false
      });
    } catch (error) {
      next(error);
    }
  }
);

/* ---------- Current User ---------- */

app.get(
  "/me",
  requireAuth,
  async (req, res, next) => {
    try {
      await ensureAccounts(
        req.user._id
      );

      const accounts =
        await Account.find({
          userId:
            req.user._id
        }).sort({
          currency: 1
        });

      res.json({
        ok: true,

        user:
          publicUser(
            req.user
          ),

        accounts,

        mode: "SANDBOX",

        realFundsEnabled:
          false
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   PASSWORD RESET — SANDBOX
========================================================= */

/*
 * Sandbox password reset only.
 *
 * The SANDBOX_RESET_KEY must live in
 * Abasthan environment variables.
 *
 * Never put the real key in GitHub.
 */

app.post(
  "/sandbox/request-password-reset",
  async (req, res, next) => {
    try {
      const email =
        String(
          req.body.email || ""
        )
          .trim()
          .toLowerCase();

      const resetKey =
        String(
          req.body.resetKey || ""
        ).trim();

      if (
        !SANDBOX_RESET_KEY ||
        resetKey !==
          SANDBOX_RESET_KEY
      ) {
        return res
          .status(403)
          .json({
            ok: false,
            error:
              "Invalid sandbox reset key."
          });
      }

      const user =
        await User.findOne({
          email
        });

      /*
       * Do not reveal whether
       * an email exists.
       */

      if (!user) {
        return res.json({
          ok: true,

          message:
            "If the account exists, a reset request has been created."
        });
      }

      const rawToken =
        crypto
          .randomBytes(32)
          .toString("hex");

      await PasswordReset.deleteMany({
        userId:
          user._id,

        usedAt: null
      });

      await PasswordReset.create({
        tokenHash:
          sha256(rawToken),

        userId:
          user._id,

        expiresAt:
          new Date(
            Date.now() +
              30 * 60 * 1000
          )
      });

      /*
       * Sandbox only:
       * return the reset token.
       *
       * Production should use
       * a trusted email provider.
       */

      res.json({
        ok: true,

        mode: "SANDBOX",

        resetToken:
          rawToken,

        message:
          "Sandbox password reset created."
      });
    } catch (error) {
      next(error);
    }
  }
);

/* ---------- Complete Password Reset ---------- */

app.post(
  "/sandbox/reset-password",
  async (req, res, next) => {
    try {
      const token =
        String(
          req.body.token || ""
        ).trim();

      const password =
        String(
          req.body.password || ""
        );

      if (
        !token ||
        password.length < 10
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "A valid reset token and password of at least 10 characters are required."
          });
      }

      const reset =
        await PasswordReset.findOne({
          tokenHash:
            sha256(token),

          usedAt: null,

          expiresAt: {
            $gt: new Date()
          }
        });

      if (!reset) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Invalid or expired reset token."
          });
      }

      const user =
        await User.findById(
          reset.userId
        );

      if (!user) {
        return res
          .status(404)
          .json({
            ok: false,
            error:
              "Account not found."
          });
      }

      user.passwordHash =
        await bcrypt.hash(
          password,
          12
        );

      await user.save();

      reset.usedAt =
        new Date();

      await reset.save();

      /*
       * Invalidate all sessions
       * after password change.
       */

      await AuthToken.deleteMany({
        userId:
          user._id
      });

      await audit({
        userId:
          user._id,

        actorId:
          user._id,

        action:
          "SANDBOX_PASSWORD_RESET",

        ip:
          req.ip
      });

      res.json({
        ok: true,

        message:
          "Password reset successfully."
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   KYC
========================================================= */

app.get(
  "/kyc",
  requireAuth,
  async (req, res, next) => {
    try {
      let profile =
        await KycProfile.findOne({
          userId:
            req.user._id
        });

      if (!profile) {
        profile =
          await KycProfile.create({
            userId:
              req.user._id,

            status:
              req.user.kycStatus ||
              "not_started"
          });
      }

      res.json({
        ok: true,
        kyc: profile
      });
    } catch (error) {
      next(error);
    }
  }
);

app.post(
  "/kyc/submit",
  requireAuth,
  async (req, res, next) => {
    try {
      let profile =
        await KycProfile.findOne({
          userId:
            req.user._id
        });

      if (!profile) {
        profile =
          await KycProfile.create({
            userId:
              req.user._id
          });
      }

      profile.status =
        "pending";

      profile.submittedAt =
        new Date();

      await profile.save();

      req.user.kycStatus =
        "pending";

      await req.user.save();

      await audit({
        userId:
          req.user._id,

        actorId:
          req.user._id,

        action:
          "KYC_SUBMITTED",

        ip:
          req.ip
      });

      res.json({
        ok: true,
        kyc: profile
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   ACCOUNTS
========================================================= */

app.get(
  "/accounts",
  requireAuth,
  async (req, res, next) => {
    try {
      await ensureAccounts(
        req.user._id
      );

      const accounts =
        await Account.find({
          userId:
            req.user._id
        }).sort({
          currency: 1
        });

      res.json({
        ok: true,

        accounts,

        mode: "SANDBOX",

        realFundsEnabled:
          false
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   SANDBOX BTC DEPOSITS
========================================================= */

/*
 * Creates a pending simulated BTC deposit.
 *
 * It does NOT credit the balance.
 */

app.post(
  "/deposits/btc",
  requireAuth,
  async (req, res, next) => {
    try {
      const amount =
        Number(
          req.body.amount
        );

      if (
        !validBtcAmount(
          amount
        )
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Enter a valid BTC amount greater than 0 and no more than 100 BTC."
          });
      }

      await ensureAccounts(
        req.user._id
      );

      const deposit =
        await Deposit.create({
          userId:
            req.user._id,

          asset:
            "BTC",

          amount,

          address:
            null,

          txid:
            null,

          status:
            "pending",

          mode:
            "SANDBOX",

          confirmations:
            0,

          requiredConfirmations:
            3,

          creditApplied:
            false
        });

      await audit({
        userId:
          req.user._id,

        actorId:
          req.user._id,

        action:
          "SANDBOX_BTC_DEPOSIT_CREATED",

        details: {
          depositId:
            String(
              deposit._id
            ),

          amount
        },

        ip:
          req.ip
      });

      res
        .status(201)
        .json({
          ok: true,

          mode:
            "SANDBOX",

          realFundsEnabled:
            false,

          message:
            "Simulated BTC deposit created and is pending confirmation.",

          deposit
        });
    } catch (error) {
      next(error);
    }
  }
);

/* ---------- Confirm Deposit ---------- */

app.post(
  "/deposits/btc/:id/confirm",
  requireAuth,
  async (req, res, next) => {
    const session =
      await mongoose.startSession();

    try {
      let result = null;

      await session.withTransaction(
        async () => {
          /*
           * IMPORTANT:
           * Only a pending deposit with
           * creditApplied=false can be
           * processed.
           *
           * This prevents duplicate
           * credits during concurrent
           * requests.
           */

          const deposit =
            await Deposit.findOne({
              _id:
                req.params.id,

              userId:
                req.user._id,

              status:
                "pending",

              creditApplied:
                false
            }).session(
              session
            );

          if (!deposit) {
            const existing =
              await Deposit.findOne({
                _id:
                  req.params.id,

                userId:
                  req.user._id
              }).session(
                session
              );

            if (
              existing &&
              existing.status ===
                "confirmed" &&
              existing.creditApplied
            ) {
              result = {
                alreadyProcessed:
                  true,

                deposit:
                  existing
              };

              return;
            }

            const error =
              new Error(
                existing
                  ? "Only pending deposits can be confirmed."
                  : "Deposit not found."
              );

            error.statusCode =
              existing
                ? 400
                : 404;

            throw error;
          }

          const account =
            await Account.findOne({
              userId:
                req.user._id,

              currency:
                "BTC"
            }).session(
              session
            );

          if (!account) {
            const error =
              new Error(
                "BTC account not found."
              );

            error.statusCode =
              404;

            throw error;
          }

          account.balance =
            Number(
              account.balance
            ) +
            Number(
              deposit.amount
            );

          await account.save({
            session
          });

          deposit.status =
            "confirmed";

          deposit.confirmations =
            deposit.requiredConfirmations;

          deposit.creditApplied =
            true;

          await deposit.save({
            session
          });

          await Ledger.create(
            [
              {
                userId:
                  req.user._id,

                currency:
                  "BTC",

                type:
                  "deposit",

                amount:
                  deposit.amount,

                referenceId:
                  String(
                    deposit._id
                  ),

                description:
                  "Simulated sandbox BTC deposit confirmed."
              }
            ],
            {
              session
            }
          );

          result = {
            alreadyProcessed:
              false,

            deposit
          };
        }
      );

      await session.endSession();

      if (
        result.alreadyProcessed
      ) {
        return res.json({
          ok: true,

          alreadyProcessed:
            true,

          mode:
            "SANDBOX",

          deposit:
            result.deposit
        });
      }

      await audit({
        userId:
          req.user._id,

        actorId:
          req.user._id,

        action:
          "SANDBOX_BTC_DEPOSIT_CONFIRMED",

        details: {
          depositId:
            String(
              result.deposit._id
            ),

          amount:
            result.deposit.amount
        },

        ip:
          req.ip
      });

      res.json({
        ok: true,

        mode:
          "SANDBOX",

        realFundsEnabled:
          false,

        message:
          "Simulated BTC deposit confirmed and credited.",

        deposit:
          result.deposit
      });
    } catch (error) {
      await session.endSession();

      next(error);
    }
  }
);

/* ---------- Deposit History ---------- */

app.get(
  "/deposits",
  requireAuth,
  async (req, res, next) => {
    try {
      const deposits =
        await Deposit.find({
          userId:
            req.user._id
        }).sort({
          createdAt: -1
        });

      res.json({
        ok: true,
        deposits
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   SANDBOX BTC WITHDRAWALS
========================================================= */

/*
 * Phase 1:
 *
 * - No real BTC is sent.
 * - Balance reservation,
 *   withdrawal creation and
 *   ledger entry occur inside
 *   one MongoDB transaction.
 */

app.post(
  "/withdrawals/btc",
  requireAuth,
  async (req, res, next) => {
    const session =
      await mongoose.startSession();

    try {
      const amount =
        Number(
          req.body.amount
        );

      const address =
        String(
          req.body.address || ""
        ).trim();

      if (
        !validBtcAmount(
          amount
        )
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Enter a valid BTC withdrawal amount."
          });
      }

      if (
        !address ||
        address.length < 10 ||
        address.length > 120
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Enter a valid BTC destination address."
          });
      }

      let withdrawal = null;

      await session.withTransaction(
        async () => {
          const account =
            await Account.findOne({
              userId:
                req.user._id,

              currency:
                "BTC"
            }).session(
              session
            );

          if (!account) {
            const error =
              new Error(
                "BTC account not found."
              );

            error.statusCode =
              404;

            throw error;
          }

          if (
            Number(
              account.balance
            ) < amount
          ) {
            const error =
              new Error(
                "Insufficient BTC balance."
              );

            error.statusCode =
              400;

            throw error;
          }

          /*
           * Reserve the amount.
           */

          account.balance =
            Number(
              account.balance
            ) - amount;

          await account.save({
            session
          });

          withdrawal =
            await Withdrawal.create(
              [
                {
                  userId:
                    req.user._id,

                  asset:
                    "BTC",

                  amount,

                  address,

                  txid:
                    null,

                  status:
                    "pending",

                  mode:
                    "SANDBOX"
                }
              ],
              {
                session
              }
            );

          withdrawal =
            withdrawal[0];

          await Ledger.create(
            [
              {
                userId:
                  req.user._id,

                currency:
                  "BTC",

                type:
                  "withdrawal",

                amount:
                  -amount,

                referenceId:
                  String(
                    withdrawal._id
                  ),

                description:
                  "Sandbox BTC withdrawal request."
              }
            ],
            {
              session
            }
          );
        }
      );

      await session.endSession();

      await audit({
        userId:
          req.user._id,

        actorId:
          req.user._id,

        action:
          "SANDBOX_BTC_WITHDRAWAL_CREATED",

        details: {
          withdrawalId:
            String(
              withdrawal._id
            ),

          amount,

          address
        },

        ip:
          req.ip
      });

      res
        .status(201)
        .json({
          ok: true,

          mode:
            "SANDBOX",

          realFundsEnabled:
            false,

          message:
            "Simulated BTC withdrawal request created.",

          withdrawal
        });
    } catch (error) {
      await session.endSession();

      next(error);
    }
  }
);

/* ---------- Withdrawal History ---------- */

app.get(
  "/withdrawals",
  requireAuth,
  async (req, res, next) => {
    try {
      const withdrawals =
        await Withdrawal.find({
          userId:
            req.user._id
        }).sort({
          createdAt: -1
        });

      res.json({
        ok: true,
        withdrawals
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   TRANSACTIONS
========================================================= */

app.get(
  "/transactions",
  requireAuth,
  async (req, res, next) => {
    try {
      const transactions =
        await Ledger.find({
          userId:
            req.user._id
        }).sort({
          createdAt: -1
        });

      res.json({
        ok: true,
        transactions
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   LOGOUT
========================================================= */

app.post(
  "/logout",
  requireAuth,
  async (req, res, next) => {
    try {
      await AuthToken.deleteOne({
        _id:
          req.authToken._id
      });

      res.json({
        ok: true,

        message:
          "Logged out successfully."
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   ADMIN
========================================================= */

/* ---------- Users ---------- */

app.get(
  "/admin/users",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
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
        ok: true,
        users
      });
    } catch (error) {
      next(error);
    }
  }
);

/* ---------- Pending Withdrawals ---------- */

app.get(
  "/admin/withdrawals",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    try {
      const withdrawals =
        await Withdrawal.find({
          status:
            "pending"
        }).sort({
          createdAt: -1
        });

      res.json({
        ok: true,
        withdrawals
      });
    } catch (error) {
      next(error);
    }
  }
);

/* ---------- Reject Withdrawal ---------- */

app.post(
  "/admin/withdrawals/:id/reject",
  requireAuth,
  requireAdmin,
  async (req, res, next) => {
    const session =
      await mongoose.startSession();

    try {
      let rejectedWithdrawal =
        null;

      await session.withTransaction(
        async () => {
          const withdrawal =
            await Withdrawal.findOne({
              _id:
                req.params.id,

              status:
                "pending"
            }).session(
              session
            );

          if (!withdrawal) {
            const error =
              new Error(
                "Pending withdrawal not found."
              );

            error.statusCode =
              404;

            throw error;
          }

          if (
            withdrawal.mode !==
            "SANDBOX"
          ) {
            const error =
              new Error(
                "Only sandbox withdrawals can be rejected by this route."
              );

            error.statusCode =
              400;

            throw error;
          }

          const account =
            await Account.findOne({
              userId:
                withdrawal.userId,

              currency:
                "BTC"
            }).session(
              session
            );

          if (!account) {
            const error =
              new Error(
                "BTC account not found."
              );

            error.statusCode =
              404;

            throw error;
          }

          /*
           * Refund the reserved
           * sandbox balance.
           */

          account.balance =
            Number(
              account.balance
            ) +
            Number(
              withdrawal.amount
            );

          await account.save({
            session
          });

          withdrawal.status =
            "rejected";

          withdrawal.rejectionReason =
            String(
              req.body.reason ||
                "Rejected by administrator."
            )
              .trim()
              .slice(0, 500);

          await withdrawal.save({
            session
          });

          await Ledger.create(
            [
              {
                userId:
                  withdrawal.userId,

                currency:
                  "BTC",

                type:
                  "withdrawal_refund",

                amount:
                  withdrawal.amount,

                referenceId:
                  `refund-${withdrawal._id}`,

                description:
                  "Sandbox withdrawal refund."
              }
            ],
            {
              session
            }
          );

          rejectedWithdrawal =
            withdrawal;
        }
      );

      await session.endSession();

      await audit({
        userId:
          rejectedWithdrawal.userId,

        actorId:
          req.user._id,

        action:
          "SANDBOX_WITHDRAWAL_REJECTED",

        details: {
          withdrawalId:
            String(
              rejectedWithdrawal._id
            ),

          amount:
            rejectedWithdrawal.amount,

          reason:
            rejectedWithdrawal.rejectionReason
        },

        ip:
          req.ip
      });

      res.json({
        ok: true,

        withdrawal:
          rejectedWithdrawal
      });
    } catch (error) {
      await session.endSession();

      next(error);
    }
  }
);

/* =========================================================
   CITYFIVE AI
========================================================= */

let aiClient = null;

if (OPENAI_API_KEY) {
  aiClient =
    new OpenAI({
      apiKey:
        OPENAI_API_KEY
    });
}

app.post(
  "/ai/chat",
  requireAuth,
  async (req, res, next) => {
    try {
      if (!aiClient) {
        return res
          .status(503)
          .json({
            ok: false,
            error:
              "CityFive AI is not configured yet."
          });
      }

      const message =
        String(
          req.body.message || ""
        ).trim();

      if (
        !message ||
        message.length > 4000
      ) {
        return res
          .status(400)
          .json({
            ok: false,
            error:
              "Enter a message up to 4000 characters."
          });
      }

      const accounts =
        await Account.find({
          userId:
            req.user._id
        }).lean();

      const deposits =
        await Deposit.find({
          userId:
            req.user._id
        })
          .sort({
            createdAt: -1
          })
          .limit(10)
          .lean();

      const withdrawals =
        await Withdrawal.find({
          userId:
            req.user._id
        })
          .sort({
            createdAt: -1
          })
          .limit(10)
          .lean();

      /*
       * Only send the AI the
       * information it actually
       * needs.
       */

      const safeContext = {
        user: {
          name:
            req.user.name,

          kycStatus:
            req.user.kycStatus,

          accountStatus:
            req.user.accountStatus
        },

        accounts:
          accounts.map(
            (account) => ({
              currency:
                account.currency,

              balance:
                account.balance
            })
          ),

        recentDeposits:
          deposits.map(
            (deposit) => ({
              amount:
                deposit.amount,

              asset:
                deposit.asset,

              status:
                deposit.status,

              confirmations:
                deposit.confirmations,

              requiredConfirmations:
                deposit.requiredConfirmations,

              createdAt:
                deposit.createdAt
            })
          ),

        recentWithdrawals:
          withdrawals.map(
            (withdrawal) => ({
              amount:
                withdrawal.amount,

              asset:
                withdrawal.asset,

              status:
                withdrawal.status,

              createdAt:
                withdrawal.createdAt
            })
          )
      };

      const response =
        await aiClient.responses.create(
          {
            model:
              OPENAI_MODEL,

            instructions:
              "You are CityFive AI, a support assistant for a cryptocurrency platform. " +
              "The current application is a SANDBOX and has no real BTC funds. " +
              "Never claim that sandbox balances are real. " +
              "Never promise investment returns, guaranteed profits, or financial outcomes. " +
              "You may explain account status, deposits, withdrawals, KYC, and transaction history using the supplied context. " +
              "You cannot approve withdrawals, change balances, create transactions, or access private keys. " +
              "If asked to perform a financial action, tell the user to use the appropriate CityFive workflow.",

            input: [
              {
                role:
                  "user",

                content: [
                  {
                    type:
                      "input_text",

                    text:
                      `Account context: ${JSON.stringify(
                        safeContext
                      )}`
                  },

                  {
                    type:
                      "input_text",

                    text:
                      message
                  }
                ]
              }
            ]
          }
        );

      res.json({
        ok: true,

        message:
          response.output_text ||
          "I couldn't generate a response."
      });
    } catch (error) {
      next(error);
    }
  }
);

/* =========================================================
   ERROR HANDLING
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

    const status =
      Number(
        error.statusCode ||
          500
      );

    res
      .status(status)
      .json({
        ok: false,

        error:
          status >= 500
            ? "Server error."
            : error.message
      });
  }
);

/* =========================================================
   START SERVER
========================================================= */

async function start() {
  await mongoose.connect(
    MONGO_URI
  );

  console.log(
    "DB connected"
  );

  console.log(
    "Platform mode: SANDBOX"
  );

  console.log(
    "Real funds enabled: false"
  );

  app.listen(
    PORT,
    "0.0.0.0",
    () => {
      console.log(
        `Server listening on port ${PORT}`
      );
    }
  );
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
