import mongoose from "mongoose";
import dotenv from "dotenv";

// Load environment variables
dotenv.config();

// Get MongoDB URI from environment or fallback to localhost for development
const MONGODB_URI = process.env.NODE_ENV === 'production' 
  ? process.env.MONGODB_URI 
  : (process.env.MONGODB_LOCAL || "mongodb://localhost:27017/codecollab");

// Function to check if we can connect to remote MongoDB
async function testMongoDBConnection(uri) {
  try {
    const testConnection = await mongoose.connect(uri, {
      serverSelectionTimeoutMS: 5000, // 5 second timeout for testing
      connectTimeoutMS: 5000,
    });
    await testConnection.disconnect();
    return true;
  } catch (error) {
    console.log(`Failed to connect to ${uri}:`, error.message);
    return false;
  }
}

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
    required: function() {
      // Email is not required for GitHub users since they might not have public email
      return this.authType !== 'github';
    },
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
  githubId: {
    type: String,
    required: false,
    index: true, // Add index for faster lookup
  },
  username: {
    type: String,
    required: false, // GitHub username
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
    enum: ["local", "google", "github"],
    default: "local",
  },
  // Subscription information for pro features
  subscription: {
    isPro: {
      type: Boolean,
      default: false
    },
    planType: {
      type: String,
      enum: ['free', 'pro', 'premium'],
      default: 'free'
    },
    subscriptionId: String, // Razorpay subscription ID
    paymentId: String, // Last payment ID
    subscriptionStart: Date,
    subscriptionEnd: Date,
    autoRenew: {
      type: Boolean,
      default: true
    },
    razorpayCustomerId: String, // Razorpay customer ID
    // Pro feature usage tracking
    features: {
      aiChatEnabled: {
        type: Boolean,
        default: false
      },
      aiCodeAnalysisEnabled: {
        type: Boolean,
        default: false
      },
      unlimitedRooms: {
        type: Boolean,
        default: false
      },
      prioritySupport: {
        type: Boolean,
        default: false
      },
      advancedCollaboration: {
        type: Boolean,
        default: false
      }
    },
    // Usage limits and tracking
    limits: {
      aiRequestsPerDay: {
        type: Number,
        default: 0
      },
      roomsCreated: {
        type: Number,
        default: 0
      },
      maxRoomCapacity: {
        type: Number,
        default: 4
      },
      dailyAiUsage: {
        date: Date,
        count: {
          type: Number,
          default: 0
        }
      },
      // Voice chat trial tracking
      voiceChatTrial: {
        totalMinutesUsed: {
          type: Number,
          default: 0
        },
        trialStartDate: {
          type: Date,
          default: null
        },
        currentSessionStart: {
          type: Date,
          default: null
        },
        hasUsedTrial: {
          type: Boolean,
          default: false
        }
      },
      // Daily AI chat limits for free users
      dailyAiChatUsage: {
        date: {
          type: Date,
          default: () => new Date().toDateString()
        },
        count: {
          type: Number,
          default: 0
        }
      }
    },
    paymentHistory: [{
      paymentId: String,
      orderId: String,
      amount: Number,
      currency: String,
      status: String,
      createdAt: {
        type: Date,
        default: Date.now
      }
    }]
  },
  // User preferences and settings
  preferences: {
    defaultLanguage: {
      type: String,
      default: 'javascript'
    },
    theme: {
      type: String,
      enum: ['light', 'dark', 'auto'],
      default: 'dark'
    },
    notifications: {
      email: {
        type: Boolean,
        default: true
      },
      browser: {
        type: Boolean,
        default: true
      }
    }
  },
  // Track user activity for analytics
  activity: {
    lastLogin: Date,
    totalLogins: {
      type: Number,
      default: 0
    },
    roomsJoined: {
      type: Number,
      default: 0
    },
    codeExecutions: {
      type: Number,
      default: 0
    },
    aiRequestsTotal: {
      type: Number,
      default: 0
    },
    totalLinesOfCode: {
      type: Number,
      default: 0
    },
    totalCodingTimeMinutes: {
      type: Number,
      default: 0
    },
    recentActivities: [{
      type: {
        type: String,
        enum: ['login', 'room_created', 'room_joined', 'code_executed', 'ai_request', 'file_saved', 'collaboration']
      },
      title: String,
      description: String,
      timestamp: {
        type: Date,
        default: Date.now
      },
      roomId: String,
      language: String,
      metadata: mongoose.Schema.Types.Mixed
    }],
    codingSession: {
      startTime: Date,
      lastActivity: Date,
      isActive: {
        type: Boolean,
        default: false
      }
    },
    recentCodeSnippets: [{
      code: String,
      language: String,
      roomId: String,
      roomName: String,
      timestamp: {
        type: Date,
        default: Date.now
      },
      linesOfCode: Number,
      executionTime: Number
    }]
  },
  // Password reset functionality
  passwordReset: {
    token: {
      type: String,
      required: false
    },
    tokenExpiry: {
      type: Date,
      required: false
    }
  }
});

// Add compound index for more efficient lookups
loginschema.index({ email: 1, authType: 1 });
loginschema.index({ 'passwordReset.token': 1 }); // Index for password reset tokens

// Room schema for storing room data
const roomSchema = new mongoose.Schema({
  roomId: {
    type: String,
    required: true,
    unique: true
  },
  name: {
    type: String,
    required: true
  },
  description: {
    type: String,
    required: false
  },
  hasPassword: {
    type: Boolean,
    default: false
  },
  password: {
    type: String,
    required: false
  },
  createdBy: {
    type: String, // User email or ID
    required: true
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  isActive: {
    type: Boolean,
    default: true
  },
  maxUsers: {
    type: Number,
    default: 10
  },
  // Track when room was last accessed for cleanup
  lastAccessed: {
    type: Date,
    default: Date.now
  },
  // Store room code and files
  currentCode: {
    type: String,
    default: ''
  },
  language: {
    type: String,
    default: 'javascript'
  },
  files: [{
    name: {
      type: String,
      required: true
    },
    content: {
      type: String,
      default: ''
    },
    language: {
      type: String,
      default: 'javascript'
    },
    isActive: {
      type: Boolean,
      default: true
    },
    lastModified: {
      type: Date,
      default: Date.now
    },
    createdBy: String
  }],
  // Code history for recovery
  codeHistory: [{
    code: String,
    language: String,
    timestamp: {
      type: Date,
      default: Date.now
    },
    userId: String,
    username: String,
    action: {
      type: String,
      enum: ['save', 'execute', 'auto_save', 'manual_save']
    }
  }]
});

// Add indexes for efficient room lookups
roomSchema.index({ createdBy: 1 });
roomSchema.index({ isActive: 1 });

// Voice chat room schema for tracking voice participants
const voiceChatSchema = new mongoose.Schema({
  roomId: {
    type: String,
    required: true,
    unique: true
  },
  participants: [{
    userId: {
      type: String,
      required: true
    },
    username: {
      type: String,
      required: true
    },
    socketId: {
      type: String,
      required: true
    },
    isMuted: {
      type: Boolean,
      default: false
    },
    isDeafened: {
      type: Boolean,
      default: false
    },
    joinedAt: {
      type: Date,
      default: Date.now
    }
  }],
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastActivity: {
    type: Date,
    default: Date.now
  }
});

// Index for efficient voice chat lookups
voiceChatSchema.index({ roomId: 1 });
voiceChatSchema.index({ "participants.userId": 1 });

const collection = mongoose.model("users", loginschema);
const Room = mongoose.model("rooms", roomSchema);
const VoiceChat = mongoose.model("voicechats", voiceChatSchema);

// Utility functions for activity tracking
async function trackUserActivity(userEmail, activityType, title, description, metadata = {}) {
  try {
    const activity = {
      type: activityType,
      title: title,
      description: description,
      timestamp: new Date(),
      ...metadata
    };

    await collection.updateOne(
      { email: userEmail },
      { 
        $push: { 
          "activity.recentActivities": {
            $each: [activity],
            $slice: -20 // Keep only last 20 activities
          }
        }
      }
    );
    
    console.log(`Activity tracked for ${userEmail}: ${title}`);
  } catch (error) {
    console.error("Error tracking activity:", error);
  }
}

async function startCodingSession(userEmail) {
  try {
    await collection.updateOne(
      { email: userEmail },
      { 
        $set: { 
          "activity.codingSession.startTime": new Date(),
          "activity.codingSession.lastActivity": new Date(),
          "activity.codingSession.isActive": true
        }
      }
    );
  } catch (error) {
    console.error("Error starting coding session:", error);
  }
}

async function updateCodingSession(userEmail) {
  try {
    const user = await collection.findOne({ email: userEmail });
    if (user?.activity?.codingSession?.isActive) {
      const now = new Date();
      const lastActivity = user.activity.codingSession.lastActivity || user.activity.codingSession.startTime;
      const timeDiff = Math.floor((now - lastActivity) / (1000 * 60)); // minutes
      
      // Only count if less than 30 minutes gap (active coding)
      if (timeDiff <= 30) {
        await collection.updateOne(
          { email: userEmail },
          { 
            $set: { "activity.codingSession.lastActivity": now },
            $inc: { "activity.totalCodingTimeMinutes": Math.min(timeDiff, 30) }
          }
        );
      }
    }
  } catch (error) {
    console.error("Error updating coding session:", error);
  }
}

async function endCodingSession(userEmail) {
  try {
    const user = await collection.findOne({ email: userEmail });
    if (user?.activity?.codingSession?.isActive) {
      const now = new Date();
      const startTime = user.activity.codingSession.startTime;
      const sessionTime = Math.floor((now - startTime) / (1000 * 60)); // minutes
      
      await collection.updateOne(
        { email: userEmail },
        { 
          $set: { "activity.codingSession.isActive": false },
          $inc: { "activity.totalCodingTimeMinutes": Math.min(sessionTime, 480) } // Max 8 hours per session
        }
      );
    }
  } catch (error) {
    console.error("Error ending coding session:", error);
  }
}

async function trackCodeExecution(userEmail, code, language, roomId, roomName, executionTime) {
  try {
    const linesOfCode = code.split('\n').filter(line => line.trim().length > 0).length;
    
    const codeSnippet = {
      code: code.length > 1000 ? code.substring(0, 1000) + '...' : code, // Limit storage
      language: language,
      roomId: roomId,
      roomName: roomName,
      timestamp: new Date(),
      linesOfCode: linesOfCode,
      executionTime: executionTime
    };

    await collection.updateOne(
      { email: userEmail },
      { 
        $push: { 
          "activity.recentCodeSnippets": {
            $each: [codeSnippet],
            $slice: -10 // Keep only last 10 code snippets
          }
        },
        $inc: { 
          "activity.codeExecutions": 1,
          "activity.totalLinesOfCode": linesOfCode
        }
      }
    );

    // Track activity
    await trackUserActivity(
      userEmail, 
      'code_executed', 
      `Executed ${language} code`,
      `${linesOfCode} lines in ${roomName || 'room'}`,
      { roomId, language, linesOfCode }
    );

    // Update coding session
    await updateCodingSession(userEmail);
    
  } catch (error) {
    console.error("Error tracking code execution:", error);
  }
}

// Room code persistence functions
async function saveRoomCode(roomId, code, language, userId, username, action = 'auto_save') {
  try {
    const room = await Room.findOne({ roomId: roomId });
    if (!room) {
      console.log(`Room ${roomId} not found for code save`);
      return false;
    }

    // Update current code and language
    await Room.updateOne(
      { roomId: roomId },
      { 
        $set: { 
          currentCode: code,
          language: language,
          lastAccessed: new Date()
        },
        $push: {
          codeHistory: {
            $each: [{
              code: code.length > 10000 ? code.substring(0, 10000) + '...' : code, // Limit storage
              language: language,
              timestamp: new Date(),
              userId: userId,
              username: username,
              action: action
            }],
            $slice: -20 // Keep only last 20 history entries
          }
        }
      }
    );

    console.log(`Code saved for room ${roomId} by ${username}`);
    return true;
  } catch (error) {
    console.error("Error saving room code:", error);
    return false;
  }
}

async function loadRoomCode(roomId) {
  try {
    const room = await Room.findOne({ roomId: roomId });
    if (!room) {
      return { code: '', language: 'javascript', files: [] };
    }

    // Update last accessed
    await Room.updateOne(
      { roomId: roomId },
      { $set: { lastAccessed: new Date() } }
    );

    return {
      code: room.currentCode || '',
      language: room.language || 'javascript',
      files: room.files || [],
      codeHistory: room.codeHistory || []
    };
  } catch (error) {
    console.error("Error loading room code:", error);
    return { code: '', language: 'javascript', files: [] };
  }
}

async function saveRoomFile(roomId, fileName, content, language, userId, username) {
  try {
    const room = await Room.findOne({ roomId: roomId });
    if (!room) {
      return false;
    }

    // Check if file exists
    const existingFileIndex = room.files.findIndex(file => file.name === fileName);
    
    if (existingFileIndex >= 0) {
      // Update existing file
      await Room.updateOne(
        { roomId: roomId, 'files.name': fileName },
        { 
          $set: { 
            'files.$.content': content,
            'files.$.language': language,
            'files.$.lastModified': new Date(),
            'files.$.createdBy': userId,
            lastAccessed: new Date()
          }
        }
      );
    } else {
      // Add new file
      await Room.updateOne(
        { roomId: roomId },
        { 
          $push: {
            files: {
              name: fileName,
              content: content,
              language: language,
              isActive: true,
              lastModified: new Date(),
              createdBy: userId
            }
          },
          $set: { lastAccessed: new Date() }
        }
      );
    }

    console.log(`File ${fileName} saved for room ${roomId} by ${username}`);
    return true;
  } catch (error) {
    console.error("Error saving room file:", error);
    return false;
  }
}

async function autoSaveRoomData(roomId, code, language, userId, username) {
  try {
    // Auto-save every 30 seconds or on significant changes
    await saveRoomCode(roomId, code, language, userId, username, 'auto_save');
    return true;
  } catch (error) {
    console.error("Error auto-saving room data:", error);
    return false;
  }
}

export { 
  collection, 
  collection as User, // Alias for external scripts
  Room,
  VoiceChat, 
  connectDB, 
  ensureDBConnection, 
  safeDBOperation,
  trackUserActivity,
  startCodingSession,
  updateCodingSession,
  endCodingSession,
  trackCodeExecution,
  saveRoomCode,
  loadRoomCode,
  saveRoomFile,
  autoSaveRoomData
};
