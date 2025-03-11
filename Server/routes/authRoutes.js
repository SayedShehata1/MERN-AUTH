import express from 'express';
import {
    isAuthenticated,
    login,
    logout,
    register,
    sendVerifyOtp,
    verifyEmail
} from '../controllers/authController.js';
import userAuth from '../middleware/userAuth.js';

const authRouter = express.Router();

authRouter.post('/register', register);
authRouter.post('/login', login);
authRouter.post('/logout', logout);
authRouter.post('/send-verify-otp', userAuth, sendVerifyOtp); // will call first the middleware (userAuth) send the userId in the req then call the controller sendVerifyOtp
authRouter.post('/verify-account', userAuth, verifyEmail);
authRouter.post('/is-auth', userAuth, isAuthenticated); // check if the user is authenticated

export default authRouter;
