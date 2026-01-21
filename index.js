import express from "express";
import bodyParser from "body-parser";
import authRoutes from "./routes/auth.routes.js"
import { connectDb } from "./config/db.js";
import dotenv from "dotenv"
dotenv.config()
await connectDb();

const app = express();

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));

// parse application/json
app.use(bodyParser.json());

app.use("/api/auth", authRoutes);

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`server is started on port ${PORT}`);
});
