const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const asyncHandler = require('express-async-handler');
const User = require('../models/userModel');

// register user, method POST
// Public /api/users
const registerUser = asyncHandler(async (req, res) => {
    //destructuring from body
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        res.status(400);
        throw new Error('Please add fields');
    }

    // check if user existst
    const userExists = await User.findOne({ email });
    if (userExists) {
        res.status(400);
        throw new Error('User Alreday Exissts');
    }

    // hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    //create user
    const user = await User.create({
        name,
        email,
        password: hashedPassword,
    });

    if (user) {
        res.status(201).json({
            _id: user._id,
            name: user.name,
            email: user.email,
            token: generateToken(user._id),
        });
    } else {
        res.status(400);
        throw new Error('Invalid User Data');
    }
});

// Authenticate user, method POST
// Public /api/users/login
const loginUser = asyncHandler(async (req, res) => {
    // destructuring from body
    const { email, password } = req.body;

    //check for user email
    const user = await User.findOne({ email });

    if (user && (await bcrypt.compare(password, user.password))) {
        res.status(201).json({
            _id: user._id,
            name: user.name,
            email: user.email,
            token: generateToken(user._id),
        });
    } else {
        res.status(400);
        throw new Error('Invalid Credits');
    }
});

// get user data, method GET
// PRIVATE  /api/users/me
const getMe = asyncHandler(async (req, res) => {
    const { _id, name, email } = await User.findById(req.user.id);

    res.status(200).json({
        id: _id,
        name,
        email,
    });
});

// Generate token
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: '2h',
    });
};

module.exports = {
    registerUser,
    loginUser,
    getMe,
};
