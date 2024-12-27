// product microservice authMiddleware.js
const jwt = require('jsonwebtoken');

const authenticateToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'Token required' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
	console.log(decoded)
    req.user = decoded; // Add user data to request object
    next();
  } catch (err) {
    res.status(403).json({ message: 'Invalid or expired token' });
  }
};

// product microservice validateRole.js
const validateRole = (roles) => (req, res, next) => {
	console.log(req.user.role)
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ message: 'Access denied by product service' });
    }
    next();
  };


module.exports = {authenticateToken, validateRole};
  

