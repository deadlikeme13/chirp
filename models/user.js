const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const uniqueValidator = require('mongoose-unique-validator')
var Schema = mongoose.Schema;

var userSchema = new Schema({
  username: {
    type: String,
    lowercase: true,
    trim: true,
    required: [true, 'Username is required.'],
    match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Username must be a valid email address']
    //index: true,
    //unique: true,
    //uniqueCaseInsensitive: true
  },
  password: { 
    type: String, 
    required: [true, 'Password is required.'] 
  }
  //createdAt: { type: Date, default: Date.now }
},
{
  timestamps: true
});

userSchema.pre("save", function(next) {
  if(!this.isModified("password")) {
      return next();
  }
  this.password = bcrypt.hashSync(this.password, 10);
  next();
});

//userSchema.plugin(uniqueValidator, { message: 'Error, expected {EMAIL} to be unique.' });
var User = mongoose.model('User', userSchema);

module.exports = User;