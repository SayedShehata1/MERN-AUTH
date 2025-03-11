import express from 'express';
import userAuth from '../middleware/userAuth.js';
import { getUserData } from '../controllers/userController.js';

const userRouter = express.Router();

// get here refer to the method of the request (GET, POST, PUT, DELETE)
userRouter.get('/data', userAuth, getUserData);

export default userRouter;
