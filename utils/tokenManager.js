const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const Redis = require("ioredis");

const redisClient = new Redis(process.env.REDIS_URI);

// Generate a token
const generateToken = (payload, secret, expiresIn, tokenType) => {
  const issuedAt = Math.floor(Date.now() / 1000);
  const expiresAt = issuedAt + expiresIn;

  const tokenPayload = {
    token_type: tokenType,
    exp: expiresAt,
    iat: issuedAt,
    jti: uuidv4().replace(/-/g, ""), // Unique JWT ID
    user_id: payload.id,
    role: payload.role,
  };

  return jwt.sign(tokenPayload, secret);
};

// Generate access and refresh tokens
const generateAccessToken = (payload) => 
  generateToken(payload, process.env.JWT_SECRET, 15 * 60, "access");

const generateRefreshToken = (payload) => 
  generateToken(payload, process.env.JWT_REFRESH_SECRET, 7 * 24 * 60 * 60, "refresh");

// Store refresh token in Redis
const storeRefreshToken = async (userId, refreshToken) => {
  await redisClient.set(`refresh:${userId}`, refreshToken, "EX", 7 * 24 * 60 * 60); // 7 days expiration
};

// Retrieve stored refresh token from Redis
const getStoredRefreshToken = async (userId) => {
  return await redisClient.get(`refresh:${userId}`);
};

// Revoke refresh token by deleting it from Redis
const revokeRefreshToken = async (userId) => {
  await redisClient.del(`refresh:${userId}`);
};

// Verify token
const verifyToken = (token, secret) => {
  try {
    return jwt.verify(token, secret);
  } catch (error) {
    throw new Error("Invalid token");
  }
};

module.exports = {
  generateAccessToken,
  generateRefreshToken,
  storeRefreshToken,
  getStoredRefreshToken,
  revokeRefreshToken,
  verifyToken,
};
