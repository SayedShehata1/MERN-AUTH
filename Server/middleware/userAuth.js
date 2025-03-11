import jwt from 'jsonwebtoken';

// Function to get the token from the cookie and find the userId from the token and sent it with the request
const userAuth = async (req, res, next) => {
    const { token } = req.cookies;

    if (!token) {
        return res.json({
            success: false,
            message: 'Not Authorized Login Again'
        });
    }

    try {
        // Verify the token
        // The token is verified using the JWT_SECRET key
        const tokenDecode = jwt.verify(token, process.env.JWT_SECRET);

        if (tokenDecode.id) {
            // Add the userId to the request
            req.body.userId = tokenDecode.id;
        } else {
            // If the token is not valid then return the response
            return res.json({
                success: false,
                message: 'Not Authorized Login Again'
            });
        }
        // next() will call the next function in the middleware > (the controller function)
        next();
    } catch (error) {
        return res.json({
            success: false,
            message: error.message
        });
    }
};

export default userAuth;
