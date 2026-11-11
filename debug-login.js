const mongoose = require('mongoose');
const User = require('C:/xampp/htdocs/Smart.Lend.App/models/User');

mongoose.connect('mongodb://127.0.0.1:27017/smart_lend_db').then(async () => {
  const user = await User.findOne({ email: 'admin@smartlend.local' }).select('+password');
  console.log('User:', user.username, user.email, user.role);
  
  const bcrypt = require('bcryptjs');
  const match = await bcrypt.compare('Admin12345!', user.password);
  console.log('Password match:', match);
  
  // Test the exact query used in login
  const user2 = await User.findOne({ 
    $or: [{ email: 'admin@smartlend.local' }, { username: 'admin@smartlend.local' }],
    role: 'admin'
  }).select('+password');
  console.log('Found by email:', user2 ? user2.username : 'null');
  
  const user3 = await User.findOne({ 
    $or: [{ email: 'admin' }, { username: 'admin' }],
    role: 'admin'
  }).select('+password');
  console.log('Found by username:', user3 ? user3.username : 'null');
  
  process.exit(0);
}).catch(e => { console.error(e); process.exit(1); });