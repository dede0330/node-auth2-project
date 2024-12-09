const jwt = require('jsonwebtoken');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const Users = require('../user/users-model');

const restricted = (req, res, next) => {
 const token = req.headers.authorization;
 fi (!token) {
  return res.status(401).json({ message: 'Token required' });
 }
 req.decodedJWT = decoded;
 next();
 });


const only = role_name => (req, res, next) => {
 
    if (req.decodedJwt && req.decodedJwt.role_name === role_name) {
      next();
    } else {
      res.status(403).json({ message: 'This is not for you' });
    }
}


const checkUsernameExists = (req, res, next) => {
 try {
  const { username } = req.body;
  const user = await Users.findBy({ username }).first();
  if (user) {
    req.user = user;
    next();
  }  else {
    res.status(401).json({ message: 'Invalid credentials' });
  } catch (err) {
    next(err);
}


const validateRoleName = (req, res, next) => {
  const { role_name } = req.body;
  if (!role_name || role_name.trim() === '') {
    req.body.role_name = 'student';
    next();
  } else if (role_name.trim() === 'admin') {
    res.status(422).json({ message: 'Role name can not be admin'});
  } else if (role_name.trim().length > 32) {
    res.status(422).json({ message: 'Role name can not be longer than 32 chars' });
  } else {
    req.body.role_name = role_name.trim();
    next();
  }

}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}
