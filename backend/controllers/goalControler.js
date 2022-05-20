const Goal = require('../models/goalModel');
const User = require('../models/userModel');
const asyncHandler = require('express-async-handler');

// gets Goals, route is /api/goals PRIVATE
const getGoals = asyncHandler(async (req, res) => {
    const goals = await Goal.find({ user: req.user.id });
    res.status(200).json(goals);
});

// create Goals, route is /api/goals PRIVATE
const setGoals = asyncHandler(async (req, res) => {
    if (!req.body.text) {
        res.status(400);
        throw new Error('Please Add A Text Field');
    }
    const goals = await Goal.create({
        text: req.body.text,
        user: req.user.id,
    });
    res.status(200).json(goals);
});

// updates Goals, route is /api/goals/:id PRIVATE
const updateGoals = asyncHandler(async (req, res) => {
    const goal = await Goal.findById(req.params.id);
    if (!goal) {
        res.status(400);
        throw new Error('Goal Not Found!');
    }

    const user = await User.findById(req.user.id);

    //checking for user
    if (!user) {
        res.status(401);
        throw new Error('There is no User');
    }

    //make sure that login user matches the goal user
    if (goal.user.toString() !== user.id) {
        res.status(401);
        throw new Error('User not Authorised');
    }

    const updatedGoal = await Goal.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
    });

    res.status(200).json(updatedGoal);
});

// delete Goals, route is /api/goals/:id PRIVATE
const delGoals = asyncHandler(async (req, res) => {
    const goal = await Goal.findById(req.params.id);
    if (!goal) {
        res.status(400);
        throw new Error('Goal Not Found!');
    }

    const user = await User.findById(req.user.id);

    //checking for user
    if (!user) {
        res.status(401);
        throw new Error('There is no User');
    }

    //make sure that login user matches the goal user
    if (goal.user.toString() !== user.id) {
        res.status(401);
        throw new Error('User not Authorised');
    }

    await goal.remove();
    res.status(200).json(req.params.id);
});

module.exports = {
    getGoals,
    setGoals,
    updateGoals,
    delGoals,
};
