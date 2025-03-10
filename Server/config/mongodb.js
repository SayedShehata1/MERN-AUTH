import mongoose from 'mongoose';

const connectDB = async () => {
    // add event listeners for the MongoDB connection to log the connection status to the console for debugging
    mongoose.connection.on('connected', () =>
        console.log('Database Connected')
    );

    // Connect to the MongoDB database
    await mongoose.connect(`${process.env.MONGODB_URI}/mern-auth`);
};

export default connectDB;
