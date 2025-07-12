import mongoose from "mongoose";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Get MongoDB URI from environment or fallback to localhost for development
const MONGODB_URI =
  process.env.MONGODB_URI || "mongodb://localhost:27017/codecollab";

// Cache connection for serverless environment
let cachedConnection = null;

async function connectDB() {
  // If connection exists, reuse it
  if (cachedConnection) {
    console.log("Using cached database connection");
    return cachedConnection;
  }

  // Create new connection
  try {
    const connection = await mongoose.connect(MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000,
    });
    console.log("Database connected successfully");
    cachedConnection = connection;
    return connection;
  } catch (error) {
    console.error("Database connection error:", error.message);
    throw error;
  }
}

// Establish connection
connectDB()
  .then(() => console.log("Database connection initialized"))
  .catch((err) =>
    console.error("Initial database connection failed:", err.message),
  );

const loginschema = new mongoose.Schema({
  fullname: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: false,
  },
  confirmPassword: {
    type: String,
    required: false,
  },
  googleId: {
    type: String,
    required: false,
    index: true, // Add index for faster lookup
  },
  picture: {
    type: String,
    required: false,
  },
  accessToken: {
    type: String,
    required: false,
  },
  // Add authType to distinguish between local and OAuth users
  authType: {
    type: String,
    enum: ["local", "google"],
    default: "local",
  },
});

// Add compound index for more efficient lookups
loginschema.index({ email: 1, authType: 1 });

const collection = mongoose.model("users", loginschema);

export { collection, connectDB };
