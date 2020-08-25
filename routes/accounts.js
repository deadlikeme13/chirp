var express = require('express');
var accountController = require('../controllers/accounts');
var router = express.Router();

router 
  .route('/register')
  .get(accountController.signupForm)
  .post(accountController.create)

module.exports = router;