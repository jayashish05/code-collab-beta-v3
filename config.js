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
      serverSelectionTimeoutMS: 30000, // Increased timeout for serverless cold starts
      socketTimeoutMS: 45000, // Socket timeout
      connectTimeoutMS: 30000, // Connection timeout
      maxPoolSize: 10, // Maintain up to 10 socket connections
      maxIdleTimeMS: 30000, // Close connections after 30 seconds of inactivity
      bufferCommands: false, // Disable mongoose buffering
      bufferMaxEntries: 0, // Disable mongoose buffering
      retryWrites: true, // Enable retryable writes
      w: 'majority', // Write concern
    });
    
    console.log("Database connected successfully");
    
    // Set up connection event listeners
    mongoose.connection.on('error', (err) => {
      console.error('MongoDB connection error:', err);
      cachedConnection = null; // Reset cache on error
    });
    
    mongoose.connection.on('disconnected', () => {
      console.log('MongoDB disconnected');
      cachedConnection = null; // Reset cache on disconnect
    });
    
    cachedConnection = connection;
    return connection;
  } catch (error) {
    console.error("Database connection error:", error.message);
    cachedConnection = null; // Reset cache on error
    throw error;
  }
}

// Function to ensure database connection before operations
async function ensureDBConnection() {
  try {
    if (!mongoose.connection.readyState) {
      console.log("Database not connected, attempting to connect...");
      await connectDB();
    }
    return true;
  } catch (error) {
    console.error("Failed to ensure database connection:", error);
    return false;
  }
}

// Function to safely execute database operations with retry logic
async function safeDBOperation(operation, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      // Ensure connection before operation
      const isConnected = await ensureDBConnection();
      if (!isConnected) {
        throw new Error("Database connection failed");
      }
      
      // Execute the operation with timeout
      const result = await Promise.race([
        operation(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error("Operation timeout")), 15000)
        )
      ]);
      
      return result;
    } catch (error) {
      console.error(`Database operation attempt ${i + 1} failed:`, error.message);
      
      // Reset connection cache on error
      cachedConnection = null;
      
      // If it's the last retry, throw the error
      if (i === maxRetries - 1) {
        throw error;
      }
      
      // Wait before retrying (exponential backoff)
      await new Promise(resolve => setTimeout(resolve, Math.pow(2, i) * 1000));
    }
  }
}

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

export { collection, connectDB, safeDBOperation };
