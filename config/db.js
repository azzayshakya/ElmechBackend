import mongoose from "mongoose";

export const connectDb = async () => {
    try {
        await mongoose.connect(process.env.DB_URL);
        console.log("database connected successfully.");
    } catch (error) {
        console.error("database error:", error);
        process.exit(1);
    }
};
