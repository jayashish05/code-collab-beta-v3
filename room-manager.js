#!/usr/bin/env node

// MongoDB Room Management Utility
import mongoose from 'mongoose';
import dotenv from 'dotenv';

dotenv.config();

// Room schema (matching the one in config.js)
const roomSchema = new mongoose.Schema({
  roomId: { type: String, required: true, unique: true },
  name: { type: String, required: true },
  description: { type: String, required: false },
  hasPassword: { type: Boolean, default: false },
  password: { type: String, required: false },
  createdBy: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  isActive: { type: Boolean, default: true },
  maxUsers: { type: Number, default: 10 },
  lastAccessed: { type: Date, default: Date.now }
});

const Room = mongoose.model('rooms', roomSchema);

async function connectToMongoDB() {
  try {
    const MONGODB_URI = process.env.MONGODB_URI || "mongodb://localhost:27017/codecollab";
    await mongoose.connect(MONGODB_URI);
    console.log('Connected to MongoDB');
  } catch (error) {
    console.error('MongoDB connection error:', error);
    process.exit(1);
  }
}

async function listRooms() {
  try {
    const rooms = await Room.find({}).sort({ createdAt: -1 });
    
    console.log('\n📊 Room Database Status:');
    console.log(`Total rooms: ${rooms.length}`);
    
    if (rooms.length > 0) {
      console.log('\n🏠 Rooms in database:');
      rooms.forEach((room, index) => {
        console.log(`${index + 1}. Room ID: ${room.roomId}`);
        console.log(`   Name: ${room.name}`);
        console.log(`   Password Protected: ${room.hasPassword ? '🔒 Yes' : '🔓 No'}`);
        console.log(`   Created By: ${room.createdBy}`);
        console.log(`   Created: ${room.createdAt.toLocaleString()}`);
        console.log(`   Last Accessed: ${room.lastAccessed.toLocaleString()}`);
        console.log(`   Active: ${room.isActive ? '✅' : '❌'}`);
        console.log('');
      });
    } else {
      console.log('   No rooms found in database');
    }
  } catch (error) {
    console.error('Error listing rooms:', error);
  }
}

async function cleanupOldRooms(daysOld = 7) {
  try {
    const cutoffDate = new Date();
    cutoffDate.setDate(cutoffDate.getDate() - daysOld);
    
    const result = await Room.deleteMany({
      lastAccessed: { $lt: cutoffDate },
      isActive: false
    });
    
    console.log(`\n🧹 Cleanup completed: Removed ${result.deletedCount} old rooms`);
  } catch (error) {
    console.error('Error during cleanup:', error);
  }
}

async function createTestRoom() {
  try {
    const testRoom = new Room({
      roomId: '999999',
      name: 'Test Room - MongoDB Integration',
      description: 'A test room to verify MongoDB storage',
      hasPassword: true,
      password: 'test123',
      createdBy: 'test@example.com',
      isActive: true
    });
    
    await testRoom.save();
    console.log('✅ Test room created successfully');
  } catch (error) {
    if (error.code === 11000) {
      console.log('⚠️  Test room already exists');
    } else {
      console.error('Error creating test room:', error);
    }
  }
}

async function main() {
  const command = process.argv[2] || 'list';
  
  await connectToMongoDB();
  
  switch (command) {
    case 'list':
      await listRooms();
      break;
    case 'cleanup':
      await listRooms();
      await cleanupOldRooms();
      await listRooms();
      break;
    case 'test':
      await createTestRoom();
      await listRooms();
      break;
    default:
      console.log('Usage: node room-manager.js [list|cleanup|test]');
  }
  
  await mongoose.disconnect();
  console.log('Disconnected from MongoDB');
}

main().catch(console.error);
