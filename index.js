const express = require("express");
const cors = require("cors");
const connectDB = require("./config/db"); // Import the database connection function
const cookieParser = require("cookie-parser");
const dotenv = require("dotenv");

const authRoutes = require("./routes/AuthRoutes");
const talkWithUsRoutes = require("./routes/talkWithUsRoutes");
const commentRoutes = require("./routes/ElmechCommentRoute");
const getUserQueriesRoutes = require("./routes/GetUserQueriesRoute");
const GetElmechCommentRoute = require("./routes/GetElmechComments");
const refreshToken = require("./routes/RefreshToken");
const logOutRoute = require("./routes/LogoutRoutes");
const errorHandler = require("./middleware/errorHandler");

dotenv.config();

const app = express();

// Middleware
app.use(express.json());
app.use(cookieParser());
app.use(
    cors({
        origin: ["http://localhost:5173","https://elmech.live"], // Adjust this to your frontend URL
        methods: ["GET", "POST", "PUT", "DELETE"],
        credentials: true,
    })
);

// Connect to the database
connectDB();
app.get('/', (req, res) => {
    res.send(`Your Elemech backend is running `);
  });

// Routes
app.use("/api/auth", authRoutes);
app.use("/api/auth", refreshToken);
app.use("/api/auth", logOutRoute); // Use the logout route here
app.use("/api/talk-with-us", talkWithUsRoutes);
app.use("/api/add-your-comment", commentRoutes);
app.use("/api/get-user-queries", getUserQueriesRoutes);
app.use("/api/get-elmech-comments", GetElmechCommentRoute);

// Global Error Handler
app.use(errorHandler);

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
