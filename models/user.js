const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const isEmail = require('validator/lib/isEmail');
const AuthError = require('../errors/AuthError');

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    minlength: 2,
    maxlength: 30,
  },
  email: {
    type: String,
    required: true,
    unique: true,
    validate: {
      validator: (email) => isEmail(email),
      message: 'Некорректый адрес почты',
    },
  },
  password: {
    type: String,
    required: true,
    select: false,
  },
});

userSchema.statics.findUserByCredentials = function (email, password) {
  return this.findOne({ email }).select('+password')
    .then((selectedUser) => {
      if (!selectedUser) {
        return Promise.reject(new AuthError('Неправильная почта или пароль'));
      }
      return bcrypt.compare(password, selectedUser.password)
        .then((matched) => {
          if (!matched) {
            return Promise.reject(new AuthError('Неправильная почта или пароль'));
          }
          return selectedUser;
        });
    });
};

module.exports = mongoose.model('user', userSchema);
