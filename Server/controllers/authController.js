import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';
import transporter from '../config/nodemailer.js';

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

        // Check if the password is correct or not using bcrypt compare
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
