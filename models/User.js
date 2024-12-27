const mongoose = require("mongoose");
const bcrypt = require("bcrypt");

const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["USER", "SHOP_OWNER", "ADMIN"], default: "USER" },
  name: { type: String },
  age: { type: Number },
  location: { type: String },
  profileFileId: { type: String },
  shopName: { type: String },
  shopDescription: { type: String },
  shopAddress: { type: String },
  createdAt: { type: Date, default: Date.now },
});

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  this.password = await bcrypt.hash(this.password, 10);
  next();
});

module.exports = mongoose.model("User", userSchema);
