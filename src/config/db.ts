import mongoose from 'mongoose';
import dotenv from 'dotenv';
import { config } from './test-config';

dotenv.config();

let isDBConnected = false;

const connectDB = async () => {
    try {
        await mongoose.connect(config.MONGODB_URI, {
            dbName: 'user-auth',
        });
        console.log("MongoDB connected");
        isDBConnected = true;
    } catch (error) {
        console.error("MongoDB connection error:", error);
        isDBConnected = false;
    }
};

export { connectDB, isDBConnected };
