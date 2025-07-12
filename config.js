import mongoose from "mongoose";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Get MongoDB URI from environment or fallback to localhost for development
const MONGODB_URI =
  process.env.MONGODB_URI || "mongodb://localhost:27017/codecollab";

// Cache connection for serverless environment
let cachedConnection = null;

// Establish connection and handle initial connection
let isConnecting = false;

async function connectDB() {
  // If connection exists and is ready, reuse it
  if (cachedConnection && mongoose.connection.readyState === 1) {
    console.log("Using cached database connection");
    return cachedConnection;
  }

  // If already connecting, wait for it
  if (isConnecting) {
    console.log("Connection in progress, waiting...");
    // Wait for connection to complete
    let attempts = 0;
    while (isConnecting && attempts < 30) {
      await new Promise(resolve => setTimeout(resolve, 1000));
      attempts++;
    }
    if (cachedConnection && mongoose.connection.readyState === 1) {
      return cachedConnection;
    }
  }

  // Create new connection
  isConnecting = true;
  try {
    console.log("Creating new database connection...");
    console.log("MongoDB URI:", MONGODB_URI ? 'Set' : 'Not set');
    
    // Close any existing connection first
    if (mongoose.connection.readyState !== 0) {
      await mongoose.disconnect();
    }

    const connection = await mongoose.connect(MONGODB_URI, {
      serverSelectionTimeoutMS: 30000, // Increased timeout for serverless cold starts
      socketTimeoutMS: 45000, // Socket timeout
      connectTimeoutMS: 30000, // Connection timeout
      maxPoolSize: 10, // Maintain up to 10 socket connections
      maxIdleTimeMS: 30000, // Close connections after 30 seconds of inactivity
      bufferCommands: false, // Disable mongoose buffering
      retryWrites: true, // Enable retryable writes
      w: 'majority', // Write concern
    });
    
    console.log("Database connected successfully");
    console.log("Connection state:", mongoose.connection.readyState);
    
    // Set up connection event listeners
    mongoose.connection.on('error', (err) => {
      console.error('MongoDB connection error:', err);
      cachedConnection = null; // Reset cache on error
      isConnecting = false;
    });
    
    mongoose.connection.on('disconnected', () => {
      console.log('MongoDB disconnected');
      cachedConnection = null; // Reset cache on disconnect
      isConnecting = false;
    });
    
    mongoose.connection.on('connected', () => {
      console.log('MongoDB connected');
    });
    
    cachedConnection = connection;
    isConnecting = false;
    return connection;
  } catch (error) {
    console.error("Database connection error:", error.message);
    console.error("Database connection error stack:", error.stack);
    cachedConnection = null; // Reset cache on error
    isConnecting = false;
    throw error;
  }
}

// Function to ensure database connection before operations
async function ensureDBConnection() {
  try {
    // Check if connection is ready (state 1 = connected)
    if (mongoose.connection.readyState === 1) {
      console.log("Database already connected, state:", mongoose.connection.readyState);
      return true;
    }
    
    console.log("Database not connected (state:", mongoose.connection.readyState, "), attempting to connect...");
    await connectDB();
    
    // Verify connection is now ready
    if (mongoose.connection.readyState === 1) {
      console.log("Database connection established successfully");
      return true;
    } else {
      console.error("Database connection failed, state:", mongoose.connection.readyState);
      return false;
    }
  } catch (error) {
    console.error("Failed to ensure database connection:", error);
    return false;
  }
}

// Function to safely execute database operations with retry logic
async function safeDBOperation(operation, maxRetries = 3) {
  for (let i = 0; i < maxRetries; i++) {
    try {
      console.log(`Database operation attempt ${i + 1}/${maxRetries}`);
      
      // Ensure connection before operation
      const isConnected = await ensureDBConnection();
      if (!isConnected) {
        throw new Error("Database connection failed");
      }
      
      // Verify we have a valid collection
      if (!collection) {
        throw new Error("Database collection not available");
      }
      
      // Execute the operation with timeout
      const result = await Promise.race([
        operation(),
        new Promise((_, reject) => 
          setTimeout(() => reject(new Error("Operation timeout after 15 seconds")), 15000)
        )
      ]);
      
      console.log("Database operation completed successfully");
      return result;
    } catch (error) {
      console.error(`Database operation attempt ${i + 1} failed:`, error.message);
      
      // Reset connection cache on error
      cachedConnection = null;
      
      // If it's the last retry, throw the error
      if (i === maxRetries - 1) {
        console.error("All database operation attempts failed");
        throw error;
      }
      
      // Wait before retrying (exponential backoff)
      const waitTime = Math.pow(2, i) * 1000;
      console.log(`Waiting ${waitTime}ms before retry...`);
      await new Promise(resolve => setTimeout(resolve, waitTime));
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

export { collection, connectDB, ensureDBConnection, safeDBOperation };
