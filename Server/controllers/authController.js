import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';
import {
    EMAIL_VERIFY_TEMPLATE,
    PASSWORD_RESET_TEMPLATE
} from '../config/emailTemplates.js';

export const register = async (req, res) => {
    const { name, email, password } = req.body;

    // Check if any field is missing
    if (!name || !email || !password) {
        return res.json({
            success: false,
            message: 'Missing Details'
        });
    }

    try {
        // Check if user already exists
        const existingUser = await userModel.findOne({ email });

        if (existingUser) {
            return res.json({
                success: false,
                message: 'User already exists'
            });
        }

        // Hash the password before saving it to the database with 10 ( medium number ) rounds of salt generation
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save the user to the database
        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        // Generate a token for the user
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
            expiresIn: '7d'
        });

        // Send the token in a HTTP-only cookie to prevent XSS attacks and access from JavaScript
        res.cookie('token', token, {
            httpOnly: true, // will be accessible only by the server side (prevents XSS attacks)
            secure: process.env.NODE_ENV === 'production', // will be yes > work with https in case of production only
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict', // will be none > work with cross-origin requests in case of production only
            maxAge: 7 * 24 * 60 * 60 * 1000 // set the cookie to expire in 7 days
        });

        // Sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to Sayed Auth',
            text: `Welcome to Sayed Auth Website! Your account has been created with the email address: ${email}`
        };

        await transporter.sendMail(mailOptions);

        // Send a success message after sending the welcome email
        return res.json({
            success: true,
            message: 'User registered successfully'
        });
    } catch (error) {
        // Send an error message
        res.json({
            success: false,
            message: error.message
        });
    }
};

export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({
            success: false,
            message: 'Email and Password are required'
        });
    }

    try {
        // Check if user exists
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({
                success: false,
                message: 'Invalid email'
            });
        }

        // Check if the password is correct or not : using bcrypt compare
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({
                success: false,
                message: 'Invalid password'
            });
        }

        // Generate a token for the user
        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
            expiresIn: '7d'
        });

        // Send the token to the HTTP-only cookie
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000
        });

        return res.json({
            success: true,
            message: 'User logged in'
        });
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        });
    }
};

export const logout = async (req, res) => {
    try {
        // Clear the cookie to log the user out
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict'
        });

        return res.json({
            success: true,
            message: 'Logged Out'
        });
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        });
    }
};

// Send Verification OTP to the user's Email
export const sendVerifyOtp = async (req, res) => {
    try {
        // Get the userId from the request body (sent by the middleware)
        const { userId } = req.body;

        const user = await userModel.findById(userId);

        if (user.isAccountVerified) {
            return res.json({
                success: false,
                message: 'Account Already Verified'
            });
        }

        // Generate a 6 digit OTP
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.verifyOtp = otp;
        // Set the OTP to expire in 24 hours
        user.verifyOtpExpireAt = Date.now() + 24 * 60 * 60 * 1000;

        // Save the user with the new OTP
        await user.save();

        // Send the OTP to the user's email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            // text: `Your OTP is ${otp}. Verify your account using this OTP`,
            html: EMAIL_VERIFY_TEMPLATE.replace('{{otp}}', otp).replace(
                '{{email}}',
                user.email
            )
        };

        await transporter.sendMail(mailOptions);

        res.json({
            success: true,
            message: 'Verification OTP Sent on Email'
        });
    } catch (error) {
        res.json({
            success: false,
            message: error.message
        });
    }
};

// Verify User OTP Account
export const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return res.json({
            success: false,
            message: 'Missing Details'
        });
    }

    try {
        const user = await userModel.findById(userId);
        if (!user) {
            return res.json({
                success: false,
                message: 'User Not Found'
            });
        }
        if (user.verifyOtp === '' || user.verifyOtp !== otp) {
            return res.json({
                success: false,
                message: 'Invalid OTP'
            });
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({
                success: false,
                message: 'OTP Expired'
            });
        }

        // Set the user account to verified and clear the OTP fields
        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;
        // Save the user to the database
        await user.save();

        return res.json({
            success: true,
            message: 'Email Verified Successfully'
        });
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        });
    }
};

// Check if user is authenticated
export const isAuthenticated = async (req, res) => {
    try {
        // will be authenticated only if the user is logged in (token is present in the cookie)
        // it will happen when the middleware userAuth will be called successfully
        return res.json({
            success: true
        });
    } catch (error) {
        res.json({
            success: false,
            message: error.message
        });
    }
};

// Send OTP to Reset Password
export const sendResetOtp = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.json({
            success: false,
            message: 'Email is required'
        });
    }

    try {
        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({
                success: false,
                message: 'User not found'
            });
        }

        // Generate a 6 digit OTP
        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        // Set the Reset OTP to expire in 15 minutes
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000;

        // Save the user with the new OTP
        await user.save();

        // Send the OTP to the user's email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Password Reset OTP',
            // text: `Your OTP for resetting your password is ${otp}. use this OTP to proceed with resetting your password.`
            html: PASSWORD_RESET_TEMPLATE.replace('{{otp}}', otp).replace(
                '{{email}}',
                user.email
            )
        };

        await transporter.sendMail(mailOptions);

        res.json({
            success: true,
            message: 'OTP sent to your email'
        });
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        });
    }
};

// Reset User Password
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.json({
            success: false,
            message: 'Email, OTP, and new password are required'
        });
    }

    try {
        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({
                success: false,
                message: 'User not found'
            });
        }

        if (user.resetOtp === '' || user.resetOtp !== otp) {
            return res.json({
                success: false,
                message: 'Invalid OTP'
            });
        }
        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({
                success: false,
                message: 'OTP Expired'
            });
        }

        // Hash the new password before saving it to the database
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        user.password = hashedPassword;
        // Clear the OTP fields
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;

        // Save the user to the database
        await user.save();

        return res.json({
            success: true,
            message: 'Password has been reset successfully '
        });
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        });
    }
};
