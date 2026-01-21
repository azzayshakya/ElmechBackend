import { registerUser, loginUser } from "../services/auth.service.js";

export const register = async (req, res) => {
  try {
    const user = await registerUser(req.body);

    res.status(201).json({
      success: true,
      message: "User registered successfully",
      userId: user._id
    });
  } catch (err) {
    console.log(err)
    res.status(400).json({
      success: false,
      message: err.message
    });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const { user, token } = await loginUser(email, password);

    res.cookie("access_token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.status(200).json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id,
        name: `${user.firstName} ${user.lastName}`,
        role: user.userRole
      }
    });
  } catch (err) {
    res.status(401).json({
      success: false,
      message: err.message
    });
  }
};

export const logout = async (req, res) => {
  res.clearCookie("access_token");

  res.status(200).json({
    success: true,
    message: "Logout successful"
  });
};
