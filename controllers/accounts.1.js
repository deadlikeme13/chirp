var express = require('express');

exports.signupForm = function(req, res) {
    res.render('accounts/new');
};

exports.create = function(req, res) {
    console.log(req.body)

    res.end
};