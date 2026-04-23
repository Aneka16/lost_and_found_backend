const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();
app.use(express.json());
app.use(cors());

/* =======================
   MongoDB Connection
======================= */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("DB Connected"))
  .catch(err => console.log(err));

/* =======================
   USER SCHEMA
======================= */
const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String
});

const User = mongoose.model("User", userSchema);

/* =======================
   ITEM SCHEMA
======================= */
const itemSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  itemName: String,
  description: String,
  type: { type: String, enum: ["Lost", "Found"] },
  location: String,
  date: String,
  contactInfo: String
});

const Item = mongoose.model("Item", itemSchema);

/* =======================
   AUTH MIDDLEWARE
======================= */
const auth = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token)
    return res.status(401).json({ msg: "No token" });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ msg: "Invalid token" });
  }
};

/* =======================
   AUTH ROUTES
======================= */

// REGISTER
app.post("/api/register", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password)
    return res.status(400).json({ msg: "All fields required" });

  const exist = await User.findOne({ email });
  if (exist)
    return res.status(400).json({ msg: "Email already exists" });

  const hashed = await bcrypt.hash(password, 10);

  await User.create({ name, email, password: hashed });

  res.json({ msg: "Registered successfully" });
});

// LOGIN
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ email });
  if (!user)
    return res.status(400).json({ msg: "Invalid credentials" });

  const match = await bcrypt.compare(password, user.password);
  if (!match)
    return res.status(400).json({ msg: "Invalid credentials" });

  const token = jwt.sign(
    { id: user._id },
    process.env.JWT_SECRET,
    { expiresIn: "1d" }
  );

  res.json({ token });
});

/* =======================
   ITEM ROUTES
======================= */

// ADD ITEM
app.post("/api/items", auth, async (req, res) => {
  try {
    const item = await Item.create({
      ...req.body,
      userId: req.user.id
    });
    res.json(item);
  } catch (err) {
    res.status(500).json({ msg: "Server error" });
  }
});

// GET ALL ITEMS
app.get("/api/items", async (req, res) => {
  try {
    const items = await Item.find().populate("userId", "name email");
    res.json(items);
  } catch {
    res.status(500).json({ msg: "Server error" });
  }
});

// ✅ SEARCH (MUST BE BEFORE :id)
app.get("/api/items/search", async (req, res) => {
  try {
    const { name } = req.query;

    if (!name || !name.trim()) {
      return res.status(400).json({ msg: "Search query required" });
    }

    const items = await Item.find({
      itemName: { $regex: name, $options: "i" }
    });

    res.json(items);
  } catch (err) {
    console.log(err);
    res.status(500).json({ msg: "Server error" });
  }
});

// GET ITEM BY ID
app.get("/api/items/:id", async (req, res) => {
  try {
    const item = await Item.findById(req.params.id);
    if (!item)
      return res.status(404).json({ msg: "Item not found" });

    res.json(item);
  } catch {
    res.status(500).json({ msg: "Invalid ID" });
  }
});

// UPDATE ITEM
app.put("/api/items/:id", auth, async (req, res) => {
  try {
    const item = await Item.findById(req.params.id);

    if (!item)
      return res.status(404).json({ msg: "Item not found" });

    if (item.userId.toString() !== req.user.id)
      return res.status(403).json({ msg: "Unauthorized" });

    const updated = await Item.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );

    res.json(updated);
  } catch {
    res.status(500).json({ msg: "Server error" });
  }
});

// DELETE ITEM
app.delete("/api/items/:id", auth, async (req, res) => {
  try {
    const item = await Item.findById(req.params.id);

    if (!item)
      return res.status(404).json({ msg: "Item not found" });

    if (item.userId.toString() !== req.user.id)
      return res.status(403).json({ msg: "Unauthorized" });

    await Item.findByIdAndDelete(req.params.id);

    res.json({ msg: "Item deleted" });
  } catch {
    res.status(500).json({ msg: "Server error" });
  }
});

/* =======================
   SERVER
======================= */
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log("Server running on", PORT));