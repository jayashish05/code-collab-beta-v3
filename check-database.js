#!/usr/bin/env node
import { Room, connectDB } from "./config.js";

async function checkDatabase() {
  try {
    console.log('🔍 Checking MongoDB Database...\n');
    
    await connectDB();
    console.log('✅ Connected to MongoDB');
    
    // Get all rooms
    const rooms = await Room.find().sort({ createdAt: -1 });
    
    console.log(`\n📊 Found ${rooms.length} room(s) in database:`);
    
    if (rooms.length === 0) {
      console.log('   No rooms found. Create some rooms to see them here.');
    } else {
      rooms.forEach((room, index) => {
        console.log(`\n   ${index + 1}. Room ${room.roomId}:`);
        console.log(`      Name: ${room.name}`);
        console.log(`      Password Protected: ${room.hasPassword ? '🔒 Yes' : '🔓 No'}`);
        console.log(`      Created By: ${room.createdBy}`);
        console.log(`      Created At: ${room.createdAt.toISOString()}`);
        console.log(`      Last Accessed: ${room.lastAccessed.toISOString()}`);
        console.log(`      Active: ${room.isActive ? 'Yes' : 'No'}`);
        if (room.description) {
          console.log(`      Description: ${room.description}`);
        }
      });
    }
    
    console.log('\n✨ Database check complete!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error);
    process.exit(1);
  }
}

checkDatabase();
