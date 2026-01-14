import mongoose from "mongoose";

export const connectDb = async () => {
    try {
        await mongoose.connect("mongodb://127.0.0.1:27017/myapp");
        console.log("database connected successfully.");
    } catch (error) {
        console.error("database error:", error);
        process.exit(1);
    }
};
