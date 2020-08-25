var express = require('express');
var User = require('../models/user');

exports.signupForm = function(req, res) {
    res.render('accounts/new');
};

exports.create = function(req, res) {
    var username = req.body.email;
    var password = req.body.password;

    var newUser = new User({
      username: username,
      password: password
    });

    newUser.save(function(err) {
      if (err) throw err;

      console.log('User saved successfully!');
    });

    res.redirect('/');
};