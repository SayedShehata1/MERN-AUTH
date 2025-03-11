import express from 'express';
import cors from 'cors';
import 'dotenv/config';
import cookieParser from 'cookie-parser';
import connectDB from './config/mongodb.js';
import authRouter from './routes/authRoutes.js';
import userRouter from './routes/userRoutes.js';

const app = express();
const port = process.env.PORT || 4000;
// Connect to the MongoDB database
connectDB();

// Middlewares for the server
app.use(express.json());
// Parse cookies from the HTTP request
app.use(cookieParser());
// Enable CORS for the server so that it can be accessed from any frontend
app.use(cors({ credentials: true }));

// Routes for the server to use for different API endpoints (for example : auth, user, etc.)
app.get('/', (req, res) => res.send('API Working'));
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);

// Start the server on the specified port
app.listen(port, () => console.log(`Server Started at Port : ${port}`));
