import {User} from "../models/user.model.js";
import bcrypt from "bcryptjs";
import { generateToken } from "../utils/generateToken.js";
import { deleteMediaFromCloudinary, uploadMedia } from "../utils/cloudinary.js";
import redis from "../utils/redis.js";
import jwt from "jsonwebtoken";

import transporter from "../utils/nodemailer.js";
import { EMAIL_VERIFY_TEMPLATE,PASSWORD_RESET_TEMPLATE } from "../utils/emailTemplates.js"

//1
export const register = async (req,res) => {
    try {
       
        const {name, email, password} = req.body; // patel214
        if(!name || !email || !password){
            return res.status(400).json({
                success:false,
                message:"All fields are required."
            })
        }
        const user = await User.findOne({email});
        if(user){
            return res.status(400).json({
                success:false,
                message:"User already exist with this email."
            })
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        await User.create({
            name,
            email,
            password:hashedPassword
        });
        return res.status(201).json({
            success:true,
            message:"Account created successfully."
        })
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"Failed to register"
        })
    }
}
//2
export const login = async (req,res) => {
    try {
        const {email, password} = req.body;
        if(!email || !password){
            return res.status(400).json({
                success:false,
                message:"All fields are required."
            })
        }
        const user = await User.findOne({email});
        if(!user){
            return res.status(400).json({
                success:false,
                message:"Incorrect email or password"
            })
        }
        const isPasswordMatch = await bcrypt.compare(password, user.password);
        if(!isPasswordMatch){
            return res.status(400).json({
                success:false,
                message:"Incorrect email or password"
            });
        }
        generateToken(res, user, `Welcome back ${user.name}`);


    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"Failed to login"
        })
    }
}

//3
export const logout = async (req, res) => {
  try {
    // 1. First verify we have the necessary data
    const refreshToken = req.cookies.refresh_token;
    
    if (!refreshToken) {
      console.log("No refresh token found in cookies");
      // Still clear cookies even if no refresh token
      clearCookies(res);
      return res.status(200).json({
        success: true,
        message: "Logged out successfully (no refresh token found).",
      });
    }

    // 2. Decode the refresh token to get the userId
    let userId;
    try {
      const decoded = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
      userId = decoded.userId;
    } catch (decodeError) {
      console.error("Failed to decode refresh token:", decodeError);
      // Still clear cookies even if decode fails
      clearCookies(res);
      return res.status(200).json({
        success: true,
        message: "Logged out successfully (invalid refresh token).",
      });
    }

    if (!userId) {
      console.log("No userId found in refresh token");
      clearCookies(res);
      return res.status(200).json({
        success: true,
        message: "Logged out successfully (no user ID in token).",
      });
    }

    // 3. Delete from Redis
    const redisKey = `refreshToken:${userId}`;
    console.log(`Attempting to delete Redis key: ${redisKey}`);
    
    const deleteResult = await redis.del(redisKey);
    console.log(`Redis delete result: ${deleteResult}`);

    if (deleteResult === 1) {
      console.log("Successfully deleted refresh token from Redis");
    } else {
      console.log("No refresh token found in Redis for this user");
    }

    // 4. Clear cookies
    clearCookies(res);

    return res.status(200).json({
      success: true,
      message: "Logged out successfully.",
    });

  } catch (error) {
    console.error("Full logout error:", error);
    // Still attempt to clear cookies even if error occurs
    clearCookies(res);
    return res.status(500).json({
      success: false,
      message: "An error occurred during logout",
    });
  }
};

// Helper function to clear cookies
function clearCookies(res) {
  res.clearCookie("access_token", {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
  });

  res.clearCookie("refresh_token", {
    httpOnly: true,
    sameSite: "strict",
    secure: process.env.NODE_ENV === "production",
  });
}

//4
export const getUserProfile = async (req,res) => {
    try {
        const userId = req.id;
        const user = await User.findById(userId).select("-password").populate("enrolledCourses");
        if(!user){
            return res.status(404).json({
                message:"Profile not found",
                success:false
            })
        }
        return res.status(200).json({
            success:true,
            user
        })
    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"Failed to load user"
        })
    }
}

//5
export const updateProfile = async (req,res) => {
    try {
        const userId = req.id;
        const {name} = req.body;
        const profilePhoto = req.file;

        const user = await User.findById(userId);
        if(!user){
            return res.status(404).json({
                message:"User not found",
                success:false
            }) 
        }
        // extract public id of the old image from the url is it exists;
        if(user.photoUrl){
            const publicId = user.photoUrl.split("/").pop().split(".")[0]; // extract public id
            deleteMediaFromCloudinary(publicId);
        }

        // upload new photo
        const cloudResponse = await uploadMedia(profilePhoto.path);
        const photoUrl = cloudResponse.secure_url;

        const updatedData = {name, photoUrl};
        const updatedUser = await User.findByIdAndUpdate(userId, updatedData, {new:true}).select("-password");

        return res.status(200).json({
            success:true,
            user:updatedUser,
            message:"Profile updated successfully."
        })

    } catch (error) {
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"Failed to update profile"
        })
    }
}


//send verificatio otp to the User's email
export const sendVerifyOtp = async (req, res) => {
  try {
    console.log("api req hit in backend");

    const userId = req.id || req.body._userId;
    if (!userId) {
      return res.json({ success: false, message: "User not authenticated." });
    }
    // const userId = req.userId;
    const user = await User.findById(userId);

    if (user.isAccountVerified) {
      return res.json({ success: false, message: "Account adready verified." });
    }

    const otp = String(Math.floor(100000 + Math.random() * 900000));

    user.verifyOtp = otp;
    user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Account Verification OTP",
      // text: `Your OTP is ${otp}. Verify your account using this OTP.`,
      html:EMAIL_VERIFY_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
    };

    await transporter.sendMail(mailOption);
    res.json({ success: true, message: "Verification OTP sent on Email" });

  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

//verify the email usin otp
export const verifyEmail = async (req, res) => {
  const userId = req.id;
  const {otp} = req.body;
  console.log("priniting otp : " , otp);
  console.log("priniting userID" , userId);
  
  if (!userId || !otp) {
    return res.json({ success: false, message: "Missing details." });
  }
  try {
    const user = await User.findById(userId);
    if (!user) {
      return res.json({ success: false, message: "User not found." });
    }

    if (user.verifyOtp === "" || user.verifyOtp !== otp) {
      return res.json({ success: false, message: "Invalid OTP." });
    }
    if (user.verifyOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP Expired." });
    }
    user.isAccountVerified = true;
    user.verifyOtp = "";
    user.verifyOtpExpireAt = 0;

    await user.save();
    return res.json({ success: true, message: "Email verified successfully" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

export const checkIsAuthenticated = async (req, res) => {
  try {
    return res.json({ success: true });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};

//send password reset otp
export const sendResetOtp = async (req, res) => {
  const { email } = req.body;
  console.log(email);
  if (!email) {
    return res.json({ success: false, message: "Email is required." });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User not found" });
    }
    const otp = String(Math.floor(100000 + Math.random() * 900000));

    user.resetOtp = otp;
    user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;

    await user.save();

    const mailOption = {
      from: process.env.SENDER_EMAIL,
      to: user.email,
      subject: "Password Reset OTP",
      // text: `Your OTP for resetting your password is ${otp} .Use this OTP to preceed with resetting your password.`,
      html:PASSWORD_RESET_TEMPLATE.replace("{{otp}}",otp).replace("{{email}}",user.email)
    };
    await transporter.sendMail(mailOption);
    return res.json({ success: true, message: "OTP sent to your email" });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};

//Reset User password
export const resetPassword = async (req, res) => {
  const { email, otp, newPassword } = req.body;
  if (!email || !otp || !newPassword) {
    return res.json({
      success: false,
      message: "Email,OTP,and password are required",
    });
  }
  try {
    const user = await User.findOne({ email });
    if (!user) {
      return res.json({ success: false, message: "User not found." });
    }
    if (user.resetOtp === "" || user.resetOtp !== otp) {
      return res.json({ success: false, message: "Invalid OTP." });
    }
    if (user.resetOtpExpireAt < Date.now()) {
      return res.json({ success: false, message: "OTP Expired" });
    }
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    user.password = hashedPassword;

    user.resetOtp = "";
    user.resetOtpExpireAt = 0;
    await user.save();

    return res.json({
      success: true,
      message: "Password has been reset successfully.",
    });
  } catch (error) {
    return res.json({ success: false, message: error.message });
  }
};



