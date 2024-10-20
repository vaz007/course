const jwt = require('jsonwebtoken');

function auth(req, res, next){
  
  let token;
  console.log('req.headers : ',req.headers)
  // Get token from authorization
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    token = req.headers.authorization.split(" ")[1];
  }

  // Check for token
  if(!token){
    return res.status(401).json({success: false, message: 'No token, authorization denied'});
  }

  try{
    // Verify token
    const decoded = jwt.verify(token, 'abc');

    console.log("DECODED : ",decoded)
    // Add user from payload
    req.user = decoded
    next();
  } catch(err){
    res.status(400).json({success: false, message: 'Token is not valid'})
  }
  
}

module.exports = auth;