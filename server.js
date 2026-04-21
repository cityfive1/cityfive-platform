const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');

const app = express();

// ✅ FIXED CORS (safe version)
app.use(cors({
  origin: "*"
}));

app.use(express.json());
