import express from "express";
import bodyParser from "body-parser";
import { connectDb } from "./config/db.js";
import dotenv from "dotenv"
dotenv.config()
await connectDb();

const app = express();

// parse application/x-www-form-urlencoded
app.use(bodyParser.urlencoded({ extended: true }));

// parse application/json
app.use(bodyParser.json());

app.get("/hello", async (req, res) => {
    return res.json({ data: "hello" });
});

const PORT = process.env.PORT || 8000;
app.listen(PORT, () => {
    console.log(`server is started on port ${PORT}`);
});
