const mongoose = require('mongoose');

const userSchema = mongoose.Schema(
    {
        name: {
            type: String,
            required: [true, 'Please enter a Name'],
        },
        email: {
            type: String,
            required: [true, 'Please enter a Email'],
            unique: true,
        },
        password: {
            type: String,
            required: [true, 'Please enter a Password'],
        },
    },
    {
        timestamps: true,
    }
);

module.exports = mongoose.model('User', userSchema);
