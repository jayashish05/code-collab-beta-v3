import mongoose from 'mongoose';
import { connectDB, User } from './config.js';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

async function upgradeAdminToPro() {
  try {
    console.log('Connecting to database...');
    await connectDB();
    console.log('Database connected successfully');

    const adminEmail = 'chethankrishna2022@gmail.com';

    // Find the admin user
    const adminUser = await User.findOne({ email: adminEmail });
    
    if (!adminUser) {
      console.log(`User with email ${adminEmail} not found. Please sign in first.`);
      return;
    }

    console.log(`Found admin user: ${adminUser.name} (${adminUser.email})`);
    console.log(`Current Pro status: ${adminUser.subscription?.isPro || false}`);

    // Update the user to Pro status
    const updateResult = await User.updateOne(
      { email: adminEmail },
      {
        $set: {
          'subscription.isPro': true,
          'subscription.planType': 'pro',
          'subscription.subscriptionStart': new Date(),
          'subscription.subscriptionEnd': new Date(Date.now() + 365 * 24 * 60 * 60 * 1000), // 1 year from now
          'subscription.paymentId': 'ADMIN_MANUAL_UPGRADE_' + Date.now(),
          'subscription.autoRenew': true,
          'subscription.features.aiChatEnabled': true,
          'subscription.features.aiCodeAnalysisEnabled': true,
          'subscription.features.prioritySupport': true,
          'subscription.features.advancedCollaboration': true,
        }
      }
    );

    if (updateResult.modifiedCount > 0) {
      console.log('✅ Admin user successfully upgraded to Pro!');
      
      // Verify the update
      const updatedUser = await User.findOne({ email: adminEmail });
      console.log('Updated Pro status:', updatedUser.subscription?.isPro);
      console.log('Plan type:', updatedUser.subscription?.planType);
      console.log('Subscription end:', updatedUser.subscription?.subscriptionEnd);
    } else {
      console.log('❌ No changes made to the user');
    }

  } catch (error) {
    console.error('Error upgrading admin to Pro:', error);
  } finally {
    await mongoose.connection.close();
    console.log('Database connection closed');
    process.exit(0);
  }
}

// Run the upgrade
upgradeAdminToPro();
