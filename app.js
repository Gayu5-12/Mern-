//Q1
const mongoose = require("mongoose");

// Created schema and model here
let categorySchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    unique: true
  },
  description: {
    type: String
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});
//category model created
let categoryModel = mongoose.model("categories", categorySchema);
app.post("/categories", async (req, res) => {
  try {
    const category = new categoryModel(req.body);
    await category.save();
    res.status(201).json(category);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
//get method for categories
app.get("/categories/:id", async (req, res) => {
  try {
    const category = await categoryModel.findById(req.params.id);
    if (!category) {
      return res.status(404).json({ message: "Category not found" });
    }
    res.json(category);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});
//put method for categories
app.put("/categories/:id", async (req, res) => {
  try {
    const updatedCategory = await categoryModel.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    res.json(updatedCategory);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});
//delete method for categories
app.delete("/categories/:id", async (req, res) => {
  try {
    await categoryModel.findByIdAndDelete(req.params.id);
    res.json({ message: "Category deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

//---------------------------------------------------------

//Q2 password reset

const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  otp: {
    type: String
  }
});

const User = mongoose.model("users", userSchema);
const nodemailer = require("nodemailer");

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: "gayu12@gmail.com",
    pass: "gayu123"
  }
});
const bcrypt = require("bcrypt");

app.post("/reset-password", async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    const user = await User.findOne({ email });

    if (!user || user.otp !== otp) {
      return res.status(400).json({ message: "Invalid OTP or email" });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Update password and clear OTP
    user.password = hashedPassword;
    user.otp = null;
    await user.save();

    res.json({ message: "Password reset successful" });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

//---------------------------------------------------------

//Q3 JWT Authentication
const jwt = require("jsonwebtoken");

const authenticateToken = (req, res, next) => {
  try {
    // Get Authorization header
    const authHeader = req.headers["authorization"];

    // Check if token exists
    if (!authHeader) {
      return res.status(401).json({ message: "Token missing" });
    }

    // Extract token from "Bearer <token>"
    const token = authHeader.split(" ")[1];

    if (!token) {
      return res.status(401).json({ message: "Invalid token format" });
    }

    // Verify token
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(401).json({ message: "Invalid or expired token" });
      }

      // Attach decoded data to request
      req.user = decoded;

      next(); // Continue to next middleware / route
    });

  } catch (error) {
    res.status(401).json({ message: "Authentication failed" });
  }
};
app.delete("/deleteproduct", authenticateToken, async (req, res) => {
  try {
    // Only authenticated users can access this route
    res.json({ message: "Product deleted successfully" });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

//---------------------------------------------------------

//API Pagination for Products
app.get("/products", async (req, res) => {
  try {
    
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 10;

    
    const skip = (page - 1) * limit;

    
    const totalProducts = await Product.countDocuments();

    const products = await Product.find()
      .skip(skip)
      .limit(limit);

    const totalPages = Math.ceil(totalProducts / limit);

    // Send response
    res.json({
      products,
      currentPage: page,
      totalPages,
      totalProducts
    });

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

Result 
{
  "products": [ ... ],
  "currentPage": 2,
  "totalPages": 10,
  "totalProducts": 50
}

//---------------------------------------------------------

//Search and Filter 
 app.get("/products/search", async (req, res) => {
  try {
    const { query, minPrice, maxPrice } = req.query;

    let filter = {};

    if (query) {
      filter.title = { $regex: query, $options: "i" };
    }

    if (minPrice || maxPrice) {
      filter.price = {};
      if (minPrice) filter.price.$gte = Number(minPrice);
      if (maxPrice) filter.price.$lte = Number(maxPrice);
    }

    const products = await Product.find(filter);
    res.json(products);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

//---------------------------------------------------------

//Error Handling Middleware

const validateSignup = (req, res, next) => {
  const { username, email, password } = req.body;

  const usernameRegex = /^[a-zA-Z0-9]{3,}$/;
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  const passwordRegex = /^(?=.*\d).{8,}$/;

  if (!username || !usernameRegex.test(username)) {
    return res.status(400).json({ message: "Invalid username" });
  }

  if (!email || !emailRegex.test(email)) {
    return res.status(400).json({ message: "Invalid email" });
  }

  if (!password || !passwordRegex.test(password)) {
    return res.status(400).json({ message: "Invalid password" });
  }

  next();
};


//---------------------------------------------------------

//Global Error Handling 
const errorHandler = (err, req, res, next) => {
  const statusCode = err.statusCode || 500;

  console.error(`[${new Date().toISOString()}]`, err.message);

  if (process.env.NODE_ENV === "production") {
    res.status(statusCode).json({
      message: "Something went wrong"
    });
  } else {
    res.status(statusCode).json({
      message: err.message,
      stack: err.stack
    });
  }
};

app.use(errorHandler);


//---------------------------------------------------------

//protected routes 
import { useContext } from "react";
import { Navigate } from "react-router-dom";
import { AuthContext } from "./AuthContext";

function ProtectedRoute({ children }) {
  const { isAuthenticated, loading } = useContext(AuthContext);

  if (loading) {
    return <div>Loading...</div>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/signin" replace />;
  }

  return children;
}

export default ProtectedRoute;

//---------------------------------------------------------

// add product form 
import { useState } from "react";
import axios from "axios";

function AddProduct() {
  const [title, setTitle] = useState("");
  const [price, setPrice] = useState("");
  const [imageUrl, setImageUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = async (e) => {
    e.preventDefault();
    setMessage("");
    setError("");

    if (!title || !price || !imageUrl) {
      setError("All fields are required");
      return;
    }

    if (Number(price) <= 0) {
      setError("Price must be a positive number");
      return;
    }

    try {
      setLoading(true);

      await axios.post(
        "/products",
        { title, price, imageUrl },
        {
          headers: {
            Authorization: `Bearer ${localStorage.getItem("token")}`
          }
        }
      );

      setMessage("Product added successfully");
      setTitle("");
      setPrice("");
      setImageUrl("");
    } catch (err) {
      setError("Failed to add product");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div>
      <h2>Add Product</h2>

      {message && <p style={{ color: "green" }}>{message}</p>}
      {error && <p style={{ color: "red" }}>{error}</p>}

      <form onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Title"
          value={title}
          onChange={(e) => setTitle(e.target.value)}
        />

        <input
          type="number"
          placeholder="Price"
          value={price}
          onChange={(e) => setPrice(e.target.value)}
        />

        <input
          type="text"
          placeholder="Image URL"
          value={imageUrl}
          onChange={(e) => setImageUrl(e.target.value)}
        />

        <button type="submit" disabled={loading}>
          {loading ? "Adding..." : "Add Product"}
        </button>
      </form>
    </div>
  );
}

export default AddProduct;

//---------------------------------------------------------
//Header component
import { useContext } from "react";
import { Link } from "react-router-dom";
import { AuthContext } from "./AuthContext";

function Header() {
  const { user, logout } = useContext(AuthContext);

  return (
    <nav>
      <Link to="/">Home</Link>

      {!user ? (
        <>
          <Link to="/signin">Sign In</Link>
          <Link to="/signup">Sign Up</Link>
        </>
      ) : (
        <>
          <span>Welcome, {user.username}</span>
          <button onClick={logout}>Logout</button>
        </>
      )}
    </nav>
  );
}

export default Header;



//AuthContext
import { createContext, useState } from "react";
import { useNavigate } from "react-router-dom";

export const AuthContext = createContext();

export function AuthProvider({ children }) {
  const navigate = useNavigate();

  const [user, setUser] = useState(
    JSON.parse(localStorage.getItem("user"))
  );
  const [token, setToken] = useState(
    localStorage.getItem("token")
  );

  const logout = () => {
    localStorage.removeItem("token");
    localStorage.removeItem("user");

    setUser(null);
    setToken(null);

    navigate("/");
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        isAuthenticated: !!user,
        logout
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

//---------------------------------------------------------
//bonus question

const rateLimit = require("express-rate-limit");

const userLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: (req) => {
    if (req.user) {
      return 100;
    }
    return 20;
  },
  message: "Too many requests, please try again later"
});

app.use(userLimiter);
const multer = require("multer");
const path = require("path");

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "uploads/");
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + path.extname(file.originalname));
  }
});

const upload = multer({ storage });
const productSchema = new mongoose.Schema({
  title: String,
  price: Number,
  image: String
});

const Product = mongoose.model("products", productSchema);
app.post("/products", upload.single("image"), async (req, res) => {
  try {
    const product = new Product({
      title: req.body.title,
      price: req.body.price,
      image: req.file.path
    });

    await product.save();
    res.status(201).json(product);

  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

