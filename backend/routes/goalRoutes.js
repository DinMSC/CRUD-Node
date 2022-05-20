const express = require('express');
const router = express.Router();
const {
    getGoals,
    setGoals,
    updateGoals,
    delGoals,
} = require('../controllers/goalControler');
const { protect } = require('../middleware/authMiddleware');

// same route for the functions that do not
// need ID just the function changes
router.route('/').get(protect, getGoals).post(protect, setGoals);
router.route('/:id').put(protect, updateGoals).delete(protect, delGoals);

module.exports = router;
